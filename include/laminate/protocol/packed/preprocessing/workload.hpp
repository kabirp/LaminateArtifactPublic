#ifndef LAMINATE_PROTOCOL_PACKED_PREPROCESSING_WORKLOAD_HPP
#define LAMINATE_PROTOCOL_PACKED_PREPROCESSING_WORKLOAD_HPP

/// @file workload.hpp
/// @brief Authenticated, relocatable workload-static packed preprocessing.

#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/setup.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace laminate::protocol {

inline constexpr std::uint64_t kPackedWorkloadStaticVersion = 1;

/// Mandatory allocation and aggregate-work bounds for an untrusted artifact.
/// A decoder rejects zero limits rather than guessing a machine-wide policy.
struct PackedWorkloadStaticDecodeLimits {
    std::size_t max_artifact_bytes = 0;
    std::size_t max_slots = 0;
    std::size_t max_payload_plaintexts = 0;
    std::size_t max_payload_gates = 0;
    std::size_t max_payload_outputs = 0;
    std::size_t max_layers = 0;
    std::size_t max_layer_gates = 0;
    std::size_t max_affine_terms = 0;
    std::size_t max_storage_entries = 0;
    std::size_t max_gate_tables = 0;

    bool operator==(const PackedWorkloadStaticDecodeLimits &) const = default;
};

/// Immutable ownership of the workload-static state certified once during
/// setup. Restoration authenticates and structurally decodes these exact
/// values; it never recompiles the payload or re-derives its trace layout.
class CertifiedPackedWorkloadStatic {
  public:
    CertifiedPackedWorkloadStatic(
        const CertifiedPackedWorkloadStatic &) = default;
    CertifiedPackedWorkloadStatic &operator=(
        const CertifiedPackedWorkloadStatic &) = default;
    CertifiedPackedWorkloadStatic(
        CertifiedPackedWorkloadStatic &&) noexcept = default;
    CertifiedPackedWorkloadStatic &operator=(
        CertifiedPackedWorkloadStatic &&) noexcept = default;

    const payload::PayloadCircuit &payload() const;
    const payload::LayeredCircuit &circuit() const;
    const payload::CanonicalTraceLayout &trace_layout() const;
    const payload::LayerDimensions &output_dimensions() const;
    const PublicSetup &public_setup() const;

    const Digest &payload_digest() const;
    const Digest &layered_digest() const;
    const Digest &circuit_digest() const;
    const Digest &setup_digest() const;
    const Digest &semantic_identity() const;

  private:
    struct State;
    explicit CertifiedPackedWorkloadStatic(
        std::shared_ptr<const State> state);
    const State &state() const;

    std::shared_ptr<const State> state_;

    friend CertifiedPackedWorkloadStatic certify_packed_workload_static(
        payload::PayloadCircuit, payload::LayeredCircuit, PublicSetup);
    friend CertifiedPackedWorkloadStatic
    decode_authenticated_packed_workload_static(
        std::span<const std::uint8_t>, const Digest &, const Digest &,
        const PackedWorkloadStaticDecodeLimits &);
    friend std::vector<std::uint8_t> encode_packed_workload_static(
        const CertifiedPackedWorkloadStatic &);
};

/// Validate the compilation/setup pair and derive the canonical trace layout
/// once, then transfer every workload-static object into immutable ownership.
CertifiedPackedWorkloadStatic certify_packed_workload_static(
    payload::PayloadCircuit payload, payload::LayeredCircuit circuit,
    PublicSetup public_setup);

/// Canonical v1 encoding. It uses an eight-byte magic, little-endian u64
/// framing, an explicit u64 version, a semantic identity, and a separately
/// domain-separated SHA-256 checksum.
std::vector<std::uint8_t> encode_packed_workload_static(
    const CertifiedPackedWorkloadStatic &workload);

/// Derive the smallest nonzero limits that decode the supplied certified
/// workload. `encoded_artifact_bytes` is the exact size of the canonical
/// artifact already encoded by the caller; this routine does not encode it a
/// second time. Aggregate affine-term and trace-storage limits are summed with
/// overflow checks across the complete workload.
PackedWorkloadStaticDecodeLimits
packed_workload_static_decode_requirements(
    const CertifiedPackedWorkloadStatic &workload,
    std::size_t encoded_artifact_bytes);

/// Authenticate the exact file and semantic identity before returning an
/// immutable restored token. Decoding is bounded and requires a byte-for-byte
/// canonical re-encoding.
CertifiedPackedWorkloadStatic decode_authenticated_packed_workload_static(
    std::span<const std::uint8_t> encoded,
    const Digest &expected_file_digest,
    const Digest &expected_semantic_identity,
    const PackedWorkloadStaticDecodeLimits &limits);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_PREPROCESSING_WORKLOAD_HPP
