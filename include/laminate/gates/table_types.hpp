#ifndef LAMINATE_GATES_TABLE_TYPES_HPP
#define LAMINATE_GATES_TABLE_TYPES_HPP

/// @file table_types.hpp
/// @brief Public types for deterministic structured gate preprocessing.

#include "laminate/basefold/basefold.hpp"
#include "laminate/basefold/foldable.hpp"
#include "laminate/gates/wide_program.hpp"
#include "laminate/transcript/hash.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace laminate::gates {

/// The query families needed by a particular Laminate protocol geometry.
enum class GateTableSet : std::uint8_t {
    /// Wide Base and Folded authenticate compact boundary operators when
    /// bounded composition succeeds, or the original local affine programs.
    Wide,
    /// Laned uses only wire-level affine predicates and affine constants.
    Laned,
};

enum class GateTableKind : std::uint8_t {
    /// Reserved wire tag, rejected by canonical Wide layouts. Composed
    /// boundary operators use the local edge and constant table kinds below.
    WideAffineWeight,
    /// Slot-independent affine constants C(output wire).
    AffineConstantUniform,
    /// Slot-dependent affine constants C(output wire, output slot).
    AffineConstantSlot,
    /// Laned coefficient weights W(output wire, source wire).
    LanedAffineWire,
    WideLocalUniformEdges, ///< W(row, source, rotation).
    WideLocalMaskEdges,    ///< W(row, source, mask), rotation zero.
    WideMaskDictionary,    ///< Shared P(mask, slot).
};

struct GateTableDescriptor {
    std::size_t layer_index = 0;
    GateTableKind kind = GateTableKind::WideAffineWeight;
    std::size_t selector = 0;
    std::size_t local_variables = 0;
    std::size_t support_size = 0;

    bool operator==(const GateTableDescriptor &) const = default;
};

struct WideLayerMetadata {
    std::size_t layer_index = 0;
    std::size_t node_count = 0;
    WideProgramDimensions dimensions{};
    Digest program_digest{};
    bool operator==(const WideLayerMetadata &) const = default;
};
struct WideMaskMetadata {
    std::size_t slots = 0;
    std::size_t mask_count = 0;
    std::size_t mask_width = 0;
    Digest dictionary_digest{};
    bool operator==(const WideMaskMetadata &) const = default;
};

/// Ordered nonempty sparse polynomials. Each has compact value/address-bit
/// columns; `selector` is its position in this list.
struct GateTableLayout {
    GateTableSet table_set = GateTableSet::Wide;
    std::vector<GateTableDescriptor> tables;
    std::vector<WideLayerMetadata> wide_layers;
    WideMaskMetadata wide_masks{};

    bool operator==(const GateTableLayout &) const = default;
};

/// One dyadic block in the shared Wide public message. Row bits are low,
/// column bits follow, and the remaining high bits select the table.
struct WidePublicTableBlock {
    std::size_t selector = 0;
    std::size_t offset = 0;
    std::size_t rows = 0;
    std::size_t columns = 0;
    bool operator==(const WidePublicTableBlock &) const = default;
};

/// Local geometry for one sparse polynomial. Laned messages split into RS
/// shards. Wide columns occupy one block of the shared public commitment;
/// their root references that global scalar vector, not a separate table.
struct SparseTableCommitment {
    std::size_t message_size = 0;
    std::size_t shard_size = 0;
    std::size_t shard_count = 0;
    std::size_t logical_width = 0;
    std::size_t physical_width = 0;
    basefold::Digest root{};
    /// Reserved metadata field. Current canonical keys require it to be empty.
    std::optional<basefold::foldable::Metadata> foldable;
    /// Present only for a table in the shared Wide public scalar vector.
    std::optional<std::size_t> wide_block_offset;

    bool operator==(const SparseTableCommitment &) const = default;
};

struct GateTableVerifierKey {
    GateTableLayout layout;
    basefold::Parameters basefold_parameters;
    Digest layout_digest{};
    std::vector<SparseTableCommitment> tables;
    basefold::foldable::Parameters foldable_parameters{};
    /// Absent for Laned and for an empty Wide public index.
    std::optional<basefold::foldable::Metadata> wide_public_commitment;

    bool operator==(const GateTableVerifierKey &) const = default;
};

} // namespace laminate::gates

#endif // LAMINATE_GATES_TABLE_TYPES_HPP
