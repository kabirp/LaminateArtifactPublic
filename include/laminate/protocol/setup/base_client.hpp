#ifndef LAMINATE_PROTOCOL_SETUP_BASE_CLIENT_HPP
#define LAMINATE_PROTOCOL_SETUP_BASE_CLIENT_HPP

/// @file base_client.hpp
/// @brief One-time-certified immutable setup for a Base client.

#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/setup.hpp"
#include "laminate/transcript/hash.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::protocol {

template <fhe::FheBackend Backend> class CertifiedBaseClientSetup;

struct BaseClientStaticSetupDecodeLimits {
    std::size_t max_artifact_bytes = 0;
    std::size_t max_slots = 0;
    std::size_t max_payload_plaintexts = 0;
    std::size_t max_payload_gates = 0;
    std::size_t max_payload_outputs = 0;
    std::size_t max_layers = 0;
    std::size_t max_layer_gates = 0;
    std::size_t max_affine_terms = 0;
    std::size_t max_storage_entries = 0;
};

/// Circuit and trace metadata decoded only after its exact bytes match a
/// client-authenticated setup digest. The constructor is private so callers
/// cannot turn unchecked circuit or alias metadata into a certification
/// bypass.
class AuthenticatedBaseClientStaticSetup {
  public:
    AuthenticatedBaseClientStaticSetup(
        const AuthenticatedBaseClientStaticSetup &) = delete;
    AuthenticatedBaseClientStaticSetup &operator=(
        const AuthenticatedBaseClientStaticSetup &) = delete;
    AuthenticatedBaseClientStaticSetup(
        AuthenticatedBaseClientStaticSetup &&) noexcept = default;
    AuthenticatedBaseClientStaticSetup &operator=(
        AuthenticatedBaseClientStaticSetup &&) noexcept = default;

    const payload::PayloadShape &payload_shape() const {
        return payload_.shape;
    }

    std::size_t layer_count() const { return circuit_.layers.size(); }

  private:
    AuthenticatedBaseClientStaticSetup(
        payload::PayloadCircuit payload,
        payload::LayeredCircuit circuit,
        payload::CanonicalTraceLayout layout, Digest setup_id,
        Digest circuit_id,
        payload::LayerDimensions output_dimensions)
        : payload_(std::move(payload)), circuit_(std::move(circuit)),
          layout_(std::move(layout)), setup_id_(setup_id),
          circuit_id_(circuit_id),
          output_dimensions_(output_dimensions) {}

    payload::PayloadCircuit payload_;
    payload::LayeredCircuit circuit_;
    payload::CanonicalTraceLayout layout_;
    Digest setup_id_{};
    Digest circuit_id_{};
    payload::LayerDimensions output_dimensions_;

    template <fhe::FheBackend Backend>
    friend class CertifiedBaseClientSetup;
    friend AuthenticatedBaseClientStaticSetup
    decode_authenticated_base_client_static_setup(
        std::span<const std::uint8_t>, const Digest &, const Digest &,
        const Digest &, const BaseClientStaticSetupDecodeLimits &);
};

template <fhe::FheBackend Backend>
std::vector<std::uint8_t> encode_base_client_static_setup(
    const CertifiedBaseClientSetup<Backend> &setup);

namespace base_client_static_setup_detail {
std::vector<std::uint8_t> encode(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const payload::CanonicalTraceLayout &layout,
    const Digest &setup_id, const Digest &circuit_id);
}

AuthenticatedBaseClientStaticSetup
decode_authenticated_base_client_static_setup(
    std::span<const std::uint8_t> encoded,
    const Digest &expected_artifact_digest,
    const Digest &expected_setup_id,
    const Digest &expected_circuit_id,
    const BaseClientStaticSetupDecodeLimits &limits);

template <fhe::FheBackend Backend>
CertifiedBaseClientSetup<Backend> certify_base_client_setup(
    payload::PayloadCircuit payload, payload::LayeredCircuit circuit,
    ClientSetup<Backend> client);

template <fhe::FheBackend Backend>
CertifiedBaseClientSetup<Backend> restore_base_client_setup(
    AuthenticatedBaseClientStaticSetup static_setup,
    ClientSetup<Backend> client);

/// Owns the exact payload, canonical compilation, public setup, secret client
/// context, and canonical trace layout accepted at one preprocessing boundary.
/// Client transitions reuse this token so they cannot accidentally
/// recompile or re-derive circuit-wide metadata for every response phase.
template <fhe::FheBackend Backend> class CertifiedBaseClientSetup {
  public:
    CertifiedBaseClientSetup(const CertifiedBaseClientSetup &) = default;
    CertifiedBaseClientSetup &
    operator=(const CertifiedBaseClientSetup &) = default;
    CertifiedBaseClientSetup(CertifiedBaseClientSetup &&) noexcept = default;
    CertifiedBaseClientSetup &
    operator=(CertifiedBaseClientSetup &&) noexcept = default;

    const payload::PayloadCircuit &payload() const { return state().payload; }

    const payload::LayeredCircuit &circuit() const {
        return state().circuit;
    }

    const payload::CanonicalTraceLayout &trace_layout() const {
        return state().layout;
    }

    const payload::CanonicalTraceLayout &layout() const {
        return state().layout;
    }

    const PublicSetup &public_setup() const {
        return state().client.public_setup;
    }

    const typename Backend::ClientContext &context() const {
        return state().client.context;
    }

    const Digest &setup_id() const { return state().setup_id; }
    const Digest &circuit_id() const { return state().circuit_id; }

    const payload::LayerDimensions &output_dimensions() const {
        return state().output_dimensions;
    }

    const payload::LayerWireSupport &output_support() const {
        return layout().wire_support.front();
    }

    std::size_t payload_output_count() const {
        return circuit().payload_output_count;
    }

    static CertifiedBaseClientSetup certify(
        payload::PayloadCircuit payload,
        payload::LayeredCircuit circuit,
        ClientSetup<Backend> client) {
        client.public_setup.validate(payload, circuit);
        if (payload.shape.kind != payload::PayloadKind::Wide ||
            circuit.shape.kind != payload::PayloadKind::Wide) {
            throw std::invalid_argument(
                "certify_base_client_setup: expected a Wide payload");
        }
        if (Backend::slot_count(client.context) !=
            payload.shape.slot_count) {
            throw std::invalid_argument(
                "certify_base_client_setup: backend and payload slot "
                "counts differ");
        }

        const Digest setup_id = setup_digest(client.public_setup);
        const Digest circuit_id = client.public_setup.circuit_digest;
        const payload::LayerDimensions output_dimensions =
            payload::layer_dimensions(circuit.layers.front());
        payload::CanonicalTraceLayout layout =
            payload::canonical_trace_layout(circuit);
        return CertifiedBaseClientSetup(std::shared_ptr<const State>(
            new State{
                std::move(payload), std::move(circuit), std::move(layout),
                std::move(client), setup_id, circuit_id,
                output_dimensions}));
    }

    static CertifiedBaseClientSetup restore(
        AuthenticatedBaseClientStaticSetup static_setup,
        ClientSetup<Backend> client) {
        if (setup_digest(client.public_setup) != static_setup.setup_id_ ||
            client.public_setup.circuit_digest !=
                static_setup.circuit_id_ ||
            Backend::slot_count(client.context) !=
                static_setup.payload_.shape.slot_count) {
            throw std::invalid_argument(
                "restore_base_client_setup: client context or public "
                "setup differs from authenticated static preprocessing");
        }
        return CertifiedBaseClientSetup(std::shared_ptr<const State>(
            new State{
                std::move(static_setup.payload_),
                std::move(static_setup.circuit_),
                std::move(static_setup.layout_), std::move(client),
                static_setup.setup_id_, static_setup.circuit_id_,
                static_setup.output_dimensions_}));
    }

  private:
    struct State {
        const payload::PayloadCircuit payload;
        const payload::LayeredCircuit circuit;
        const payload::CanonicalTraceLayout layout;
        const ClientSetup<Backend> client;
        const Digest setup_id;
        const Digest circuit_id;
        const payload::LayerDimensions output_dimensions;
    };

    explicit CertifiedBaseClientSetup(std::shared_ptr<const State> state)
        : state_(std::move(state)) {}

    const State &state() const {
        if (!state_) {
            throw std::logic_error(
                "certified Base client setup is moved from");
        }
        return *state_;
    }

    std::shared_ptr<const State> state_;
};

/// Validate all static Base client inputs exactly once, then take immutable
/// ownership of them. Dynamic response/proof checks remain online.
template <fhe::FheBackend Backend>
CertifiedBaseClientSetup<Backend> certify_base_client_setup(
    payload::PayloadCircuit payload, payload::LayeredCircuit circuit,
    ClientSetup<Backend> client) {
    return CertifiedBaseClientSetup<Backend>::certify(
        std::move(payload), std::move(circuit), std::move(client));
}

template <fhe::FheBackend Backend>
CertifiedBaseClientSetup<Backend> restore_base_client_setup(
    AuthenticatedBaseClientStaticSetup static_setup,
    ClientSetup<Backend> client) {
    return CertifiedBaseClientSetup<Backend>::restore(
        std::move(static_setup), std::move(client));
}

template <fhe::FheBackend Backend>
std::vector<std::uint8_t> encode_base_client_static_setup(
    const CertifiedBaseClientSetup<Backend> &setup) {
    return base_client_static_setup_detail::encode(
        setup.payload(), setup.circuit(), setup.layout(), setup.setup_id(),
        setup.circuit_id());
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_SETUP_BASE_CLIENT_HPP
