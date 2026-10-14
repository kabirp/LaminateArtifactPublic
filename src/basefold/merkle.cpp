#include "laminate/basefold/merkle.hpp"

#include "laminate/field/serialization.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <stdexcept>
#include <string_view>

namespace laminate::basefold {
namespace {

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

constexpr std::array<std::uint64_t, 8> kBlake2bIv{
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

constexpr std::array<std::array<std::uint8_t, 16>, 12> kBlake2bSigma{{
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}},
    {{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}},
    {{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}},
    {{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}},
    {{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}},
    {{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}},
    {{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}},
    {{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}},
    {{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}},
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}},
}};

std::uint64_t load64(std::span<const std::uint8_t, 8> bytes) {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        result |= static_cast<std::uint64_t>(bytes[index]) << (8U * index);
    }
    return result;
}

void store64(std::uint64_t word, std::span<std::uint8_t, 8> output) {
    for (std::size_t index = 0; index < 8; ++index) {
        output[index] = static_cast<std::uint8_t>(word >> (8U * index));
    }
}

void blake2b_compress(std::array<std::uint64_t, 8> &state,
                      std::span<const std::uint8_t, 128> block,
                      std::uint64_t count, bool final) {
    std::array<std::uint64_t, 16> message{};
    for (std::size_t index = 0; index < message.size(); ++index) {
        message[index] = load64(
            std::span<const std::uint8_t, 8>(block.data() + 8 * index, 8));
    }
    std::array<std::uint64_t, 16> work{};
    std::copy(state.begin(), state.end(), work.begin());
    std::copy(kBlake2bIv.begin(), kBlake2bIv.end(), work.begin() + 8);
    work[12] ^= count;
    if (final) {
        work[14] = ~work[14];
    }
    const auto mix = [&](std::size_t a, std::size_t b, std::size_t c,
                         std::size_t d, std::uint64_t x,
                         std::uint64_t y) {
        work[a] = work[a] + work[b] + x;
        work[d] = std::rotr(work[d] ^ work[a], 32);
        work[c] += work[d];
        work[b] = std::rotr(work[b] ^ work[c], 24);
        work[a] = work[a] + work[b] + y;
        work[d] = std::rotr(work[d] ^ work[a], 16);
        work[c] += work[d];
        work[b] = std::rotr(work[b] ^ work[c], 63);
    };
    for (const auto &sigma : kBlake2bSigma) {
        mix(0, 4, 8, 12, message[sigma[0]], message[sigma[1]]);
        mix(1, 5, 9, 13, message[sigma[2]], message[sigma[3]]);
        mix(2, 6, 10, 14, message[sigma[4]], message[sigma[5]]);
        mix(3, 7, 11, 15, message[sigma[6]], message[sigma[7]]);
        mix(0, 5, 10, 15, message[sigma[8]], message[sigma[9]]);
        mix(1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
        mix(2, 7, 8, 13, message[sigma[12]], message[sigma[13]]);
        mix(3, 4, 9, 14, message[sigma[14]], message[sigma[15]]);
    }
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] ^= work[index] ^ work[index + 8];
    }
}

Digest blake2b_320(std::span<const std::uint8_t> input) {
    std::array<std::uint64_t, 8> state = kBlake2bIv;
    // RFC 7693 parameter block: digest length 40, key length 0, fanout/depth 1.
    state[0] ^= 0x01010000U ^ static_cast<std::uint64_t>(Digest{}.size());
    std::uint64_t count = 0;
    while (input.size() > 128) {
        count += 128;
        blake2b_compress(
            state, std::span<const std::uint8_t, 128>(input.data(), 128),
            count, false);
        input = input.subspan(128);
    }
    std::array<std::uint8_t, 128> final_block{};
    std::copy(input.begin(), input.end(), final_block.begin());
    count += static_cast<std::uint64_t>(input.size());
    blake2b_compress(state, final_block, count, true);
    Digest result{};
    std::array<std::uint8_t, 64> full{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        store64(state[index],
                std::span<std::uint8_t, 8>(full.data() + 8 * index, 8));
    }
    std::copy_n(full.begin(), result.size(), result.begin());
    return result;
}

Digest bcs_hash(std::uint8_t domain,
                std::span<const std::uint8_t> payload) {
    constexpr std::string_view tag =
        "LaminateImpl/BaseFold/BCS16/BLAKE2b-320/v1";
    constexpr std::size_t prefix_size = tag.size() + 1 + 8;
    const std::size_t total_size = prefix_size + payload.size();
    std::array<std::uint8_t, 2048> local{};
    thread_local std::vector<std::uint8_t> large;
    std::span<std::uint8_t> input;
    if (total_size <= local.size()) {
        input = std::span<std::uint8_t>(local).first(total_size);
    } else {
        large.resize(total_size);
        input = large;
    }
    std::copy(tag.begin(), tag.end(), input.begin());
    input[tag.size()] = domain;
    const std::uint64_t length = payload.size();
    for (std::size_t byte = 0; byte < 8; ++byte) {
        input[tag.size() + 1 + byte] =
            static_cast<std::uint8_t>(length >> (8U * byte));
    }
    std::copy(payload.begin(), payload.end(),
              input.begin() + static_cast<std::ptrdiff_t>(prefix_size));
    return blake2b_320(input);
}

} // namespace

MerkleTree MerkleTree::from_levels(std::vector<std::vector<Digest>> levels,
                                   const Digest &expected_root) {
    if (levels.empty() || !is_power_of_two(levels.front().size()))
        throw std::invalid_argument("MerkleTree: invalid persisted leaf count");
    auto expected = levels.front().size();
    for (const auto &level : levels) {
        if (expected == 0 || level.size() != expected)
            throw std::invalid_argument("MerkleTree: invalid persisted levels");
        expected /= 2;
    }
    if (expected != 0 || levels.back().size() != 1 ||
        levels.back().front() != expected_root)
        throw std::invalid_argument("MerkleTree: persisted root mismatch");
    MerkleTree result;
    result.levels_ = std::move(levels);
    return result;
}

MerkleTree::MerkleTree(
    const std::vector<std::vector<std::uint8_t>> &leaves)
    : MerkleTree(leaves.size(), [&](std::size_t index) {
          return hash_leaf(leaves[index]);
      }) {}

MerkleTree::MerkleTree(
    std::size_t leaf_count,
    const std::function<Digest(std::size_t)> &hash_leaf) {
    if (!is_power_of_two(leaf_count) || !hash_leaf) {
        throw std::invalid_argument(
            "basefold::MerkleTree: leaf count must be a power of two");
    }

    levels_.emplace_back(leaf_count);
    for (std::size_t index = 0; index < leaf_count; ++index) {
        levels_.front()[index] = hash_leaf(index);
    }
    while (levels_.back().size() > 1) {
        const std::vector<Digest> &children = levels_.back();
        std::vector<Digest> parents(children.size() / 2);
        for (std::size_t index = 0; index < parents.size(); ++index) {
            parents[index] = hash_pair(
                children[2 * index], children[2 * index + 1]);
        }
        levels_.push_back(std::move(parents));
    }
}

std::vector<Digest> MerkleTree::open(std::size_t index) const {
    if (index >= leaf_count()) {
        throw std::out_of_range("basefold::MerkleTree::open: bad index");
    }
    std::vector<Digest> path;
    path.reserve(levels_.size() - 1);
    for (std::size_t level = 0; level + 1 < levels_.size(); ++level) {
        path.push_back(levels_[level][index ^ 1U]);
        index >>= 1U;
    }
    return path;
}

std::vector<MerkleNodePosition>
MerkleTree::multiproof_frontier_positions(
    std::size_t leaf_count, std::span<const std::size_t> indices) {
    if (!is_power_of_two(leaf_count) || indices.empty() ||
        indices.back() >= leaf_count ||
        !std::is_sorted(indices.begin(), indices.end()) ||
        std::adjacent_find(indices.begin(), indices.end()) != indices.end()) {
        throw std::invalid_argument(
            "basefold::MerkleTree: malformed multiproof leaf set");
    }

    std::vector<std::size_t> current(indices.begin(), indices.end());
    std::vector<MerkleNodePosition> result;
    std::size_t level = 0;
    while (leaf_count > 1) {
        std::vector<std::size_t> parents;
        parents.reserve((current.size() + 1U) / 2U);
        for (std::size_t cursor = 0; cursor < current.size();) {
            const std::size_t index = current[cursor];
            const std::size_t sibling = index ^ 1U;
            if ((index & 1U) == 0 && cursor + 1U < current.size() &&
                current[cursor + 1U] == sibling) {
                ++cursor;
            } else {
                result.push_back(MerkleNodePosition{
                    .level = level,
                    .index = sibling,
                });
            }
            parents.push_back(index >> 1U);
            ++cursor;
        }
        current = std::move(parents);
        leaf_count >>= 1U;
        ++level;
    }
    return result;
}

std::vector<Digest>
MerkleTree::open_many(std::span<const std::size_t> indices) const {
    const std::vector<MerkleNodePosition> positions =
        multiproof_frontier_positions(leaf_count(), indices);
    std::vector<Digest> result;
    result.reserve(positions.size());
    for (const MerkleNodePosition &position : positions) {
        result.push_back(levels_.at(position.level).at(position.index));
    }
    return result;
}

bool MerkleTree::verify(const Digest &root, std::size_t leaf_count,
                        std::size_t index,
                        std::span<const std::uint8_t> leaf,
                        std::span<const Digest> path) {
    return verify_hash(root, leaf_count, index,
                       hash_leaf(leaf), path);
}

bool MerkleTree::verify_hash(const Digest &root, std::size_t leaf_count,
                             std::size_t index, const Digest &leaf_hash,
                             std::span<const Digest> path) {
    try {
        if (!is_power_of_two(leaf_count) || index >= leaf_count) {
            return false;
        }
        std::size_t expected_depth = 0;
        for (std::size_t count = leaf_count; count > 1; count >>= 1U) {
            ++expected_depth;
        }
        if (path.size() != expected_depth) {
            return false;
        }

        Digest node = leaf_hash;
        for (const Digest &sibling : path) {
            node = (index & 1U) != 0 ? hash_pair(sibling, node)
                                     : hash_pair(node, sibling);
            index >>= 1U;
        }
        return node == root;
    } catch (const std::invalid_argument &) {
        return false;
    }
}

bool MerkleTree::verify_many_hashes(
    const Digest &root, std::size_t leaf_count,
    std::span<const std::size_t> indices,
    std::span<const Digest> leaf_hashes,
    std::span<const Digest> frontier) {
    try {
        if (!is_power_of_two(leaf_count) || indices.empty() ||
            indices.back() >= leaf_count ||
            !std::is_sorted(indices.begin(), indices.end()) ||
            std::adjacent_find(indices.begin(), indices.end()) !=
                indices.end() ||
            leaf_hashes.size() != indices.size()) {
            return false;
        }

        struct IndexedDigest {
            std::size_t index = 0;
            Digest digest{};
        };
        std::vector<IndexedDigest> current;
        std::vector<IndexedDigest> parents;
        current.reserve(indices.size());
        parents.reserve(indices.size());
        for (std::size_t index = 0; index < indices.size(); ++index) {
            current.push_back(IndexedDigest{indices[index],
                                            leaf_hashes[index]});
        }
        std::size_t frontier_cursor = 0;
        while (leaf_count > 1) {
            parents.clear();
            for (std::size_t cursor = 0; cursor < current.size();) {
                const std::size_t index = current[cursor].index;
                Digest left{};
                Digest right{};
                if ((index & 1U) == 0) {
                    left = current[cursor].digest;
                    if (cursor + 1U < current.size() &&
                        current[cursor + 1U].index == index + 1U) {
                        right = current[cursor + 1U].digest;
                        cursor += 2U;
                    } else {
                        if (frontier_cursor == frontier.size()) {
                            return false;
                        }
                        right = frontier[frontier_cursor++];
                        ++cursor;
                    }
                } else {
                    if (frontier_cursor == frontier.size()) {
                        return false;
                    }
                    left = frontier[frontier_cursor++];
                    right = current[cursor].digest;
                    ++cursor;
                }
                parents.push_back(IndexedDigest{
                    index >> 1U, hash_pair(left, right)});
            }
            current.swap(parents);
            leaf_count >>= 1U;
        }
        return frontier_cursor == frontier.size() && current.size() == 1U &&
               current.front().index == 0U && current.front().digest == root;
    } catch (const std::exception &) {
        return false;
    }
}

Digest MerkleTree::hash_pair(const Digest &left, const Digest &right) {
    std::array<std::uint8_t, 2 * Digest{}.size()> input{};
    std::copy(left.begin(), left.end(), input.begin());
    std::copy(right.begin(), right.end(),
              input.begin() + static_cast<std::ptrdiff_t>(left.size()));
    return bcs_hash(2, input);
}

Digest MerkleTree::hash_leaf(std::span<const std::uint8_t> leaf) {
    return bcs_hash(1, leaf);
}

Digest MerkleTree::hash_fq_leaf(std::span<const Fq> leaf) {
    thread_local std::vector<std::uint8_t> bytes;
    bytes.resize(leaf.size() * kSerializedFqBytes);
    for (std::size_t index = 0; index < leaf.size(); ++index) {
        const SerializedFq encoded = serialize(leaf[index]);
        std::copy(encoded.begin(), encoded.end(),
                  bytes.begin() + static_cast<std::ptrdiff_t>(
                                      index * encoded.size()));
    }
    return bcs_hash(1, bytes);
}

Digest MerkleTree::hash_fq2_leaf(std::span<const Fq2> leaf) {
    thread_local std::vector<std::uint8_t> bytes;
    bytes.resize(leaf.size() * kSerializedFq2Bytes);
    for (std::size_t index = 0; index < leaf.size(); ++index) {
        const SerializedFq2 encoded = serialize(leaf[index]);
        std::copy(encoded.begin(), encoded.end(),
                  bytes.begin() + static_cast<std::ptrdiff_t>(
                                      index * encoded.size()));
    }
    return bcs_hash(1, bytes);
}

Digest MerkleTree::hash_children(const Digest &left,
                                 const Digest &right) {
    return hash_pair(left, right);
}

} // namespace laminate::basefold
