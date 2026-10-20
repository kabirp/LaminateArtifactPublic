#ifndef LAMINATE_PAYLOAD_TRACE_TRACE_WIRE_SUPPORT_HPP
#define LAMINATE_PAYLOAD_TRACE_TRACE_WIRE_SUPPORT_HPP

/// @file trace_wire_support.hpp
/// @brief Canonical live-wire maps for virtually padded payload traces.

#include "laminate/fhe/value.hpp"
#include "laminate/payload/ir/layered.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace laminate::payload {

/// One half-open run of logically live trace wires in the padded layer domain.
/// `padded_begin` is the wire's protocol index; `wire_count` is the number of
/// consecutive live wires represented by the run.
struct LiveWireRange {
    std::size_t padded_begin = 0;
    std::size_t wire_count = 0;

    std::size_t padded_end() const;

    bool operator==(const LiveWireRange &) const = default;
};

/// Dense logical-live order together with its canonical embedding in a padded
/// trace-layer domain. Runs are ordered by padded index and adjacent live
/// wires belong to one run. Physical storage may further alias identical
/// logical values according to `LayerStorageLayout`.
struct LayerWireSupport {
    std::size_t padded_wire_count = 0;
    std::size_t live_wire_count = 0;
    std::vector<LiveWireRange> live_ranges;

    /// Map a padded protocol index to its dense live ordinal. A padding index
    /// returns `nullopt`; an index outside the padded domain throws.
    std::optional<std::size_t>
    live_index_of(std::size_t padded_index) const;

    /// Map a dense live ordinal back to its padded protocol index.
    std::size_t padded_index_of(std::size_t live_index) const;

    bool is_live(std::size_t padded_index) const;

    bool operator==(const LayerWireSupport &) const = default;
};

/// Setup-derived physical storage map for one logical trace layer. Padding
/// has no stored ordinal. Normally every live protocol index receives a
/// distinct ordinal in canonical live order. When an affine layer is the
/// source of a multiplication layer, byte-for-byte identical nonpadding
/// affine recipes share the ordinal of their first occurrence. Provenance is
/// logical metadata, not part of the value-producing recipe. Logical wire
/// support and protocol indices are unchanged.
struct LayerStorageLayout {
    std::size_t padded_wire_count = 0;
    std::size_t stored_wire_count = 0;
    std::vector<std::optional<std::size_t>> padded_to_stored;
    std::vector<std::size_t> representative_padded_indices;

    /// Return the physical ordinal for a live protocol index. Padding maps to
    /// `nullopt`; an index outside the padded domain throws.
    std::optional<std::size_t>
    stored_ordinal_of(std::size_t padded_index) const;

    /// Return the first protocol index represented by one physical ordinal.
    std::size_t
    representative_padded_index_of(std::size_t stored_ordinal) const;

    bool operator==(const LayerStorageLayout &) const = default;
};

/// Value counts from the setup-derived classification of one trace layer.
///
/// A logical live wire is a nonpadding protocol position. Physical storage
/// can be smaller because setup-identical values alias one record. A stored
/// value can in turn be a public plaintext rather than a ciphertext when it
/// does not depend on any encrypted client input. These distinctions matter
/// independently to GKR geometry, disk use, and proof-ingress normalization.
struct LayerTraceValueCounts {
    std::size_t virtual_wire_positions = 0;
    std::size_t logical_live_wires = 0;
    std::size_t stored_values = 0;
    std::size_t encrypted_ciphertexts = 0;

    std::size_t public_plaintext_values() const {
        return stored_values - encrypted_ciphertexts;
    }

    bool operator==(const LayerTraceValueCounts &) const = default;
};

/// Classification of one physically stored trace value. An engaged value is
/// the exact public plaintext derived during setup. `nullopt` reserves a
/// ciphertext, including when setup cannot establish a public result. Entries
/// are indexed by physical stored ordinal.
using ClassifiedTraceValue = std::optional<fhe::PublicPlaintext>;

/// Canonical logical support, physical aliases, stored-value classifications,
/// and aggregate counts for a complete trace. Deriving these together avoids
/// repeating whole-circuit analysis in cost models and setup.
struct CanonicalTraceLayout {
    std::vector<LayerWireSupport> wire_support;
    std::vector<LayerStorageLayout> storage;
    std::vector<std::vector<ClassifiedTraceValue>>
        stored_value_classifications;
    std::vector<LayerTraceValueCounts> value_counts;

    bool operator==(const CanonicalTraceLayout &) const = default;
};

/// Immutable, self-contained ownership of a circuit and its exactly derived
/// canonical trace layout. Cached consumers take the token rather than a
/// mutable `CanonicalTraceLayout`, so later mutation or destruction of the
/// caller's circuit cannot change gates or aliases after certification.
class CertifiedCanonicalTraceLayout {
  public:
    CertifiedCanonicalTraceLayout(
        const CertifiedCanonicalTraceLayout &) = default;
    CertifiedCanonicalTraceLayout &operator=(
        const CertifiedCanonicalTraceLayout &) = default;
    CertifiedCanonicalTraceLayout(
        CertifiedCanonicalTraceLayout &&) noexcept = default;
    CertifiedCanonicalTraceLayout &operator=(
        CertifiedCanonicalTraceLayout &&) noexcept = default;

    const LayeredCircuit &circuit() const;
    const CanonicalTraceLayout &layout() const;

  private:
    struct State;
    explicit CertifiedCanonicalTraceLayout(
        std::shared_ptr<const State> state);

    std::shared_ptr<const State> state_;

    friend CertifiedCanonicalTraceLayout
    derive_certified_canonical_trace_layout(const LayeredCircuit &);
    friend CertifiedCanonicalTraceLayout certify_canonical_trace_layout(
        const LayeredCircuit &, CanonicalTraceLayout);
};

/// Check the self-contained canonical range invariants of one support map.
void validate_layer_wire_support(const LayerWireSupport &support);

/// Check the self-contained ordinal and representative invariants of one
/// physical storage layout.
void validate_layer_storage_layout(const LayerStorageLayout &layout);

/// Derive and validate the canonical support map for one trace layer. The
/// circuit's `GateOrigin::Padding` outputs and input tail are virtual zeros;
/// payload and forwarding outputs remain live at their original padded
/// indices.
LayerWireSupport canonical_layer_wire_support(
    const LayeredCircuit &circuit, std::size_t layer_index);

/// Derive every layer map in GKR order. This additionally checks that each
/// omitted gate is structurally forced to zero by the circuit.
std::vector<LayerWireSupport>
canonical_trace_wire_support(const LayeredCircuit &circuit);

/// Derive the deterministic physical layout for one layer. This metadata is
/// a pure function of the canonical layered circuit and is never encoded as
/// independent setup input.
LayerStorageLayout canonical_layer_storage_layout(
    const LayeredCircuit &circuit, std::size_t layer_index);

/// Derive the physical layouts for all layers in GKR order.
std::vector<LayerStorageLayout>
canonical_trace_storage_layout(const LayeredCircuit &circuit);

/// Derive logical, physical, and budgeted ciphertext counts for every trace
/// layer. Inputs are encrypted. Public arithmetic and multiplication by
/// public zero propagate public values. All other results are budgeted as
/// ciphertexts, even if runtime arithmetic later exposes exact cancellation.
std::vector<LayerTraceValueCounts>
canonical_trace_value_counts(const LayeredCircuit &circuit);

/// Derive all canonical trace views in one circuit pass sequence.
CanonicalTraceLayout canonical_trace_layout(
    const LayeredCircuit &circuit);

/// Derive the exact layout once and seal it into a circuit-bound token.
CertifiedCanonicalTraceLayout derive_certified_canonical_trace_layout(
    const LayeredCircuit &circuit);

/// Compare a caller-supplied layout with a fresh exact derivation, then seal
/// it into a circuit-bound token. This deliberately rejects structurally
/// valid but noncanonical alias maps.
CertifiedCanonicalTraceLayout certify_canonical_trace_layout(
    const LayeredCircuit &circuit, CanonicalTraceLayout candidate);

/// Require a supplied layer map to equal the circuit-derived canonical map.
void validate_layer_wire_support(const LayeredCircuit &circuit,
                                 std::size_t layer_index,
                                 const LayerWireSupport &support);

/// Require exactly one canonical support map for every circuit layer.
void validate_trace_wire_support(
    const LayeredCircuit &circuit,
    std::span<const LayerWireSupport> support);

/// Require a supplied physical layout to equal the circuit-derived layout.
void validate_layer_storage_layout(const LayeredCircuit &circuit,
                                   std::size_t layer_index,
                                   const LayerStorageLayout &layout);

/// Require exactly one canonical physical layout for every circuit layer.
void validate_trace_storage_layout(
    const LayeredCircuit &circuit,
    std::span<const LayerStorageLayout> layouts);

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_TRACE_TRACE_WIRE_SUPPORT_HPP
