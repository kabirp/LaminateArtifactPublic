#ifndef LAMINATE_GATES_WIDE_PROGRAM_HPP
#define LAMINATE_GATES_WIDE_PROGRAM_HPP

#include "laminate/field/fpk.hpp"
#include "laminate/gates/sparse_product.hpp"
#include "laminate/payload/ir/layered.hpp"
#include "laminate/transcript/hash.hpp"

#include <functional>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace laminate::gates {

/// One dictionary is shared by all affine programs in a circuit. Entries are
/// distinct, nonuniform slot masks; uniform plaintexts become scalar edges.
class WideMaskDictionary {
  public:
    static std::shared_ptr<const WideMaskDictionary> build(
        const payload::LayeredCircuit &circuit);
    std::size_t slots() const { return slots_; }
    std::size_t size() const { return masks_.size(); }
    std::size_t padded_size() const { return padded_size_; }
    std::span<const fhe::SlotVector> masks() const { return masks_; }
    const Digest &digest() const { return digest_; }
    /// Streams the canonical nonzero P(mask,slot) entries, in address order.
    void visit_entries(
        const std::function<void(const sparse::SparseEntry &)> &visit) const;

  private:
    friend class WideProgram;
    std::size_t slots_ = 0;
    std::size_t padded_size_ = 1;
    std::vector<fhe::SlotVector> masks_;
    std::vector<std::optional<std::size_t>> plaintext_masks_;
    std::vector<std::optional<Fp>> plaintext_scalars_;
    Digest digest_{};
};

enum class WideSourceBlock : std::uint8_t { Input = 0, Internal = 1 };

struct WideProgramTerm {
    WideSourceBlock source_block = WideSourceBlock::Input;
    std::size_t source = 0;
    std::size_t rotation = 0;
    Fp coefficient = Fp::zero();
    /// Mask edges always have rotation zero. Rotation followed by masking is
    /// normalized into two primitive nodes, never a composed matrix.
    std::optional<std::size_t> mask;
};

struct WideProgramNode {
    std::vector<WideProgramTerm> terms;
    payload::AffineConstant constant = Fp::zero();
};

/// Deterministic limits for replacing a local affine DAG by sparse boundary
/// rows. Work counts visited coefficient/constant entries, not slot-expanded
/// matrix entries. Exceeding any limit retains the complete local program.
/// Zero limits disable composition. Production construction uses these fixed
/// defaults; an explicit policy is also bound into the program digest.
struct WideProgramCompositionLimits {
    std::size_t max_row_terms = 1U << 16;
    std::size_t max_retained_terms = 1U << 23;
    std::size_t max_work = 1U << 24;
    std::size_t max_constant_scalars = 1U << 20;
};

/// Peak additional resident bytes for constructing one program and its shared
/// mask dictionary, excluding the already resident input circuit. Uses only
/// structural counts, never sparse composition or slot-matrix expansion. The
/// bound covers simultaneous normalized and composed rows, one ordered merge
/// map, copied constants, vector headers, and allocator overhead. Programs are
/// constructed one layer at a time by the canonical-table and opening paths.
std::uint64_t wide_program_composition_workspace_bound(
    const payload::LayeredCircuit &circuit,
    WideProgramCompositionLimits limits = {});

/// Exact Boolean domains; all widths are positive powers of two. The public
/// matrix row address is block*row_width+index (internal=0, output=1), and its
/// source address is block*source_width+index (input=0, internal=1). Internal Z
/// has ONLY internal_width*slots entries, including zero internal padding.
struct WideProgramDimensions {
    std::size_t slots = 0;
    std::size_t input_width = 0;
    std::size_t output_width = 0;
    std::size_t internal_width = 0;
    std::size_t row_width = 0;
    std::size_t source_width = 0;
    std::size_t mask_width = 0;
    std::size_t internal_scalars = 0;
    std::size_t uniform_edge_domain = 0;
    std::size_t mask_edge_domain = 0;
    std::size_t uniform_constant_domain = 0;
    std::size_t slot_constant_domain = 0;
    std::size_t dictionary_domain = 0;

    bool operator==(const WideProgramDimensions &) const = default;
};

enum class WidePublicTable : std::uint8_t {
    UniformEdges,   ///< W(row, source, rotation), MSB-first concatenation.
    MaskEdges,      ///< W(row, source, mask), MSB-first concatenation.
    UniformConstants, ///< C(row).
    SlotConstants, ///< C(row,slot), only nonuniform constants.
};

enum class WideColumnTarget : std::uint8_t { Input, Internal, Constant };

/// Each callback transfers exactly slots field elements. A disk ScalarArray
/// adapts with read_block/write_block(row*slots, values). Callbacks must support
/// repeated reads and writes; algorithms use O(slots) field scratch space.
using WideRowReader = std::function<void(std::size_t, std::span<Fpk>)>;
using WideRowWriter = std::function<void(std::size_t, std::span<const Fpk>)>;

/// Local normalized affine program w=T w+B x+d, y=Ri w+Rx x+Rc.
/// Construction first normalizes primitive edges, then attempts bounded exact
/// sparse composition. Successful composition has no internal nodes and keeps
/// slots factored as rotations or shared masks; it never expands a slot matrix.
/// Unsupported action products or resource limits retain the local DAG. The
/// digest binds the policy, selected representation, dimensions, and dictionary.
class WideProgram {
  public:
    static WideProgram build(const payload::LayeredCircuit &circuit,
                             std::size_t layer_index,
                             std::shared_ptr<const WideMaskDictionary> masks,
                             WideProgramCompositionLimits limits = {});
    const WideProgramDimensions &dimensions() const { return dimensions_; }
    std::size_t layer_index() const { return layer_index_; }
    std::span<const WideProgramNode> nodes() const { return nodes_; }
    std::span<const WideProgramNode> outputs() const { return outputs_; }
    const WideMaskDictionary &masks() const { return *masks_; }
    const Digest &digest() const { return digest_; }

    /// Entries are coalesced and streamed in strictly increasing address
    /// order. Memory is proportional to primitive edges, not the table domain.
    void visit_entries(WidePublicTable table,
        const std::function<void(const sparse::SparseEntry &)> &visit) const;

    void apply_forward(const WideRowReader &read_input,
                       const WideRowReader &read_internal,
                       const WideRowWriter &write_internal,
                       const WideRowWriter &write_output) const;

    /// Apply local transposes in reverse circuit order. For y=A x+c, the
    /// resulting input weights are A^T chi, where chi is the MLE equality
    /// vector at output_point_msb. A weight a on u=2v+3w contributes 2a at v
    /// and 3a at w. Contributions from all uses of a node are added.
    /// The internal weights satisfy z=T^T z+Ri^T chi. This writes only those
    /// node/slot rows; input weights are B^T z+Rx^T chi and the weighted
    /// constant is <z,d>+chi^T Rc. A node is included even when its value is
    /// also an output. Output weights are generated one row at a time.
    void compute_reverse(std::span<const Fpk> output_point_msb,
                         const WideRowReader &read_internal,
                         const WideRowWriter &write_internal) const;

    /// Computes H_i(:,target) for H_i=B,T,d, respectively. For Input/Internal,
    /// target_point has log2(input/internal_width)+log2(slots) coordinates;
    /// Constant requires an empty point. Writes internal_width rows only.
    void build_internal_column(WideColumnTarget target,
                               std::span<const Fpk> target_point_msb,
                               const WideRowWriter &write_row) const;

    /// Public output-boundary contribution chi^T Rx, chi^T Ri, or chi^T Rc.
    /// This is prover/reference arithmetic, not a verifier authentication step.
    Fpk evaluate_output_column(std::span<const Fpk> output_point_msb,
                               WideColumnTarget target,
                               std::span<const Fpk> target_point_msb) const;

    /// Contract a supplied internal adjoint with B/T/d and add the known
    /// output contribution. Input and Constant recover the affine coefficient
    /// and constant; Internal equals z(target) for an honest reverse trace.
    Fpk evaluate_from_reverse(const WideRowReader &read_internal,
                             std::span<const Fpk> output_point_msb,
                             WideColumnTarget target,
                             std::span<const Fpk> target_point_msb) const;

  private:
    std::size_t layer_index_ = 0;
    WideProgramDimensions dimensions_;
    std::vector<WideProgramNode> nodes_;
    std::vector<WideProgramNode> outputs_;
    std::shared_ptr<const WideMaskDictionary> masks_;
    Digest digest_{};
};

} // namespace laminate::gates
#endif
