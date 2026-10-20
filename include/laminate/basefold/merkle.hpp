#ifndef LAMINATE_BASEFOLD_MERKLE_HPP
#define LAMINATE_BASEFOLD_MERKLE_HPP

/// @file merkle.hpp
/// @brief Binary BLAKE2b-320 Merkle commitment used by BaseFold's BCS layer.

#include "laminate/basefold/digest.hpp"
#include "laminate/field/fq2.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace laminate::basefold {

/// One node in a binary Merkle tree. Level zero contains leaves; a node at
/// level `level` covers `2^level` consecutive leaves.
struct MerkleNodePosition {
    std::size_t level = 0;
    std::size_t index = 0;

    bool operator==(const MerkleNodePosition &) const = default;
    bool operator<(const MerkleNodePosition &other) const {
        return level < other.level ||
               (level == other.level && index < other.index);
    }
};

class MerkleTree {
  public:
    /// Hash `leaves` in their supplied order. The count must be a power of two.
    explicit MerkleTree(
        const std::vector<std::vector<std::uint8_t>> &leaves);

    /// Build from already-domain-separated leaf hashes. BaseFold uses this
    /// path to hash chunks of canonically encoded native field elements.
    MerkleTree(std::size_t leaf_count,
               const std::function<Digest(std::size_t)> &hash_leaf);

    /// Restore already stored authentication nodes without rehashing them.
    /// Validates the complete power-of-two level geometry and expected root.
    /// Openings remain authenticated by the verifier against that root.
    static MerkleTree from_levels(std::vector<std::vector<Digest>> levels,
                                  const Digest &expected_root);

    const Digest &root() const { return levels_.back().front(); }
    std::size_t leaf_count() const { return levels_.front().size(); }

    /// Canonical levels from leaves through the one-node root. Persistence
    /// code uses this read-only view to retire a resident tree after writing
    /// all authentication nodes to disk.
    const std::vector<std::vector<Digest>> &levels() const {
        return levels_;
    }

    /// Return sibling hashes from the leaf level to the root.
    std::vector<Digest> open(std::size_t index) const;

    /// Return the canonical union frontier authenticating `indices`.
    /// Indices must be sorted, unique, nonempty, and in range. The result is
    /// ordered exactly like `multiproof_frontier_positions`: level by level
    /// from the leaves upward, and left to right within each level.
    std::vector<Digest>
    open_many(std::span<const std::size_t> indices) const;

    /// Derive the node positions in a canonical union frontier. No position
    /// is transmitted in a multiproof: the verifier derives this list from
    /// the expected opened leaves and consumes one digest per position.
    static std::vector<MerkleNodePosition> multiproof_frontier_positions(
        std::size_t leaf_count,
        std::span<const std::size_t> indices);

    /// Authenticate one leaf. `leaf_count` pins the expected path depth.
    static bool verify(const Digest &root, std::size_t leaf_count,
                       std::size_t index,
                       std::span<const std::uint8_t> leaf,
                       std::span<const Digest> path);

    /// Authenticate a leaf whose domain-separated hash was computed by the
    /// caller.  This keeps field-native BaseFold leaves canonical while the
    /// tree remains reusable by byte-oriented callers.
    static bool verify_hash(const Digest &root, std::size_t leaf_count,
                            std::size_t index, const Digest &leaf_hash,
                            std::span<const Digest> path);

    /// Authenticate sorted unique leaf hashes with one canonical union
    /// frontier. This rejects missing, extra, or noncanonical frontier data.
    static bool verify_many_hashes(
        const Digest &root, std::size_t leaf_count,
        std::span<const std::size_t> indices,
        std::span<const Digest> leaf_hashes,
        std::span<const Digest> frontier);

    /// Domain-separated BLAKE2b-320 leaf hash used by the BCS16 Merkle tree.
    /// Poseidon remains the in-circuit ciphertext commitment; BaseFold leaves
    /// are outside R1CS and use a byte-oriented hash for throughput.
    static Digest hash_leaf(std::span<const std::uint8_t> leaf);

    /// Allocation-reusing canonical field encoders used by BaseFold leaves.
    static Digest hash_fq_leaf(std::span<const Fq> leaf);
    static Digest hash_fq2_leaf(std::span<const Fq2> leaf);

    /// Domain-separated parent hash. External-memory builders use this to
    /// reduce a sequential stream of leaf hashes without retaining a tree.
    static Digest hash_children(const Digest &left, const Digest &right);

  private:
    MerkleTree() = default;
    static Digest hash_pair(const Digest &left, const Digest &right);

    std::vector<std::vector<Digest>> levels_;
};

} // namespace laminate::basefold

#endif // LAMINATE_BASEFOLD_MERKLE_HPP
