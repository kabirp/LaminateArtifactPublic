#ifndef LAMINATE_GATES_CANONICAL_TABLES_HPP
#define LAMINATE_GATES_CANONICAL_TABLES_HPP

/// @file canonical_tables.hpp
/// @brief Canonical sparse gate tables and deterministic BaseFold roots.
///
/// Wide tables describe bounded sparse boundary operators when composition
/// stays compact, or local affine primitives otherwise, and a shared mask
/// dictionary. Composition never enumerates paths or dense slot matrices.
/// Laned retains compact wire predicates. Sparse public address/value columns
/// use one disk-backed honest-column foldable commitment for Wide and sharded RS
/// commitments for Laned.

#include "laminate/basefold/commitment.hpp"
#include "laminate/gates/sparse_product.hpp"
#include "laminate/gates/table_types.hpp"
#include "laminate/payload/ir/layered.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace laminate::gates {

struct GateTableBuildOptions {
    basefold::Parameters basefold_parameters{};
    /// Bound the total number of nonzero entries retained across all compact
    /// polynomials. This is a preprocessing resource limit, not a protocol
    /// parameter.
    std::size_t max_message_entries = std::size_t{1} << 23;
    basefold::foldable::Parameters foldable_parameters{};
    /// Wide commitments and openings use private disk directories. A missing
    /// parent is allowed only for bounded reference instances (<= 4096 entries).
    std::filesystem::path wide_scratch_parent;
    /// Explicit total disk allowance, including all retained index objects.
    /// Zero requests the bounded-reference allowance, never target admission.
    std::uint64_t wide_max_disk_bytes = 0;
    basefold::foldable::Options wide_resources{};
    /// Worker budget for constructing the public Wide commitment only.
    /// It is not copied into the prover key or used for online openings.
    std::size_t preprocessing_threads = 1;
    /// Optional durable server-only state. Setup exports here; restore opens
    /// it and fails if missing or incompatible, without rebuilding commitments.
    std::filesystem::path prover_key_directory;
};

/// Commitment dimensions derived before any column or Merkle tree is built.
struct SparseTableShape {
    std::size_t message_size = 0;
    std::size_t shard_size = 0;
    std::size_t shard_count = 0;
    std::size_t logical_width = 0;
    std::size_t physical_width = 0;

    bool operator==(const SparseTableShape &) const = default;
};

SparseTableShape plan_sparse_table_shape(
    const GateTableDescriptor &table, GateTableSet table_set,
    const basefold::Parameters &parameters = {});

struct SparseTableProverKey {
    SparseTableCommitment verifier;
    std::optional<basefold::Commitment> commitment;
    std::vector<sparse::SparseEntry> entries;
    /// Reserved per-table storage; Wide uses the shared public commitment.
    /// Current prover keys require this field to be empty.
    std::optional<basefold::foldable::Commitment> foldable_commitment;
};

/// Server preprocessing state. The client/verifier receives only `verifier`.
struct GateTableProverKey {
    GateTableVerifierKey verifier;
    /// Declared before tables so backing arrays close before the owner removes
    /// the private directory. Copies share lifetime, never mutable filenames.
    std::shared_ptr<const std::filesystem::path> wide_directory_owner;
    std::optional<basefold::foldable::Commitment> wide_public_commitment;
    std::vector<SparseTableProverKey> tables;
    basefold::foldable::Options wide_resources{};
    std::filesystem::path wide_scratch_parent;
    std::uint64_t wide_retained_disk_bytes = 0;
};

GateTableLayout make_gate_table_layout(
    const payload::LayeredCircuit &circuit, GateTableSet table_set,
    const basefold::Parameters &parameters = {});

std::vector<std::uint8_t>
encode_canonical(const GateTableLayout &layout);
Digest digest(const GateTableLayout &layout);

/// Deterministic descending-size packing, breaking ties by table selector.
/// Throws if the blocks cannot fit the certified public commitment domain.
std::vector<WidePublicTableBlock> make_wide_public_blocks(
    const GateTableLayout &layout);

/// Check the complete shared root, exact block map and local table geometry.
/// Laned keys must have no shared Wide commitment or Wide block offsets.
bool valid_wide_public_index(const GateTableVerifierKey &key);

/// Contiguous columns of the canonical virtual public vector. Rows cover the
/// largest sparse table and grow only as needed to keep at most 256 columns.
basefold::foldable::Metadata plan_wide_public_commitment(
    const GateTableLayout &layout);

/// Durable server-only cache. The authenticated verifier projection pins the
/// PCS roots and geometry. Corrupt prover data cannot authorize a false proof.
void export_gate_table_prover_key(const GateTableProverKey &key,
                                 const std::filesystem::path &directory);
GateTableProverKey reopen_gate_table_prover_key(
    const GateTableVerifierKey &expected,
    const std::filesystem::path &directory,
    const GateTableBuildOptions &runtime_options = {});

/// Build the shared honest-column Wide index or the sharded Laned RS columns.
/// Public metadata and roots are deterministic across private directory choices.
GateTableProverKey preprocess_gate_tables(
    const payload::LayeredCircuit &circuit, GateTableSet table_set,
    const GateTableBuildOptions &options = {});

const GateTableDescriptor &find_table(
    const GateTableLayout &layout, std::size_t layer_index,
    GateTableKind kind);

const GateTableDescriptor *find_table_if(
    const GateTableLayout &layout, std::size_t layer_index,
    GateTableKind kind);

/// Validate the deterministic sharding and column geometry for one layout
/// descriptor. This checks shape only; the root is separately required to be
/// nonzero by public-setup validation.
bool valid_sparse_table_commitment(
    const GateTableDescriptor &table,
    const SparseTableCommitment &commitment,
    const basefold::Parameters &parameters);

/// Reference/prover helper for a compact sparse polynomial.
Fpk evaluate_sparse_table(std::span<const sparse::SparseEntry> entries,
                          std::size_t address_variables,
                          std::span<const Fpk> point_msb);

} // namespace laminate::gates

#endif // LAMINATE_GATES_CANONICAL_TABLES_HPP
