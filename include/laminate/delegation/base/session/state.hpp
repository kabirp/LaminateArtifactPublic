#ifndef LAMINATE_DELEGATION_BASE_SESSION_STATE_HPP
#define LAMINATE_DELEGATION_BASE_SESSION_STATE_HPP

/// @file session/state.hpp
/// @brief Move-only role state for delegated LaminateBase executions.

#include "laminate/delegation/base/transport/messages.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/protocol/storage/base_capacity.hpp"

#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace laminate::delegation {

namespace base_client_detail {
struct ClientStateAccess;
}

/// Immutable evaluation-time contract retained until the destructive Base
/// proof transition. Paths are normalized and capacity is admitted before FHE
/// evaluation begins.
class CheckpointReplayBaseServerResources {
  public:
    CheckpointReplayBaseServerResources(
        protocol::BaseProverOptions proof_options,
        protocol::BaseServerCapacityCaps capacity_caps,
        protocol::BaseServerCapacityComponents capacity_components,
        protocol::BaseServerCapacityAdmission capacity_admission)
        : proof_options_(std::move(proof_options)),
          capacity_caps_(capacity_caps),
          capacity_components_(std::move(capacity_components)),
          capacity_admission_(std::move(capacity_admission)) {}

    const protocol::BaseProverOptions &proof_options() const {
        return proof_options_;
    }
    const protocol::BaseServerCapacityCaps &capacity_caps() const {
        return capacity_caps_;
    }
    const protocol::BaseServerCapacityComponents &capacity_components()
        const {
        return capacity_components_;
    }
    const protocol::BaseServerCapacityAdmission &capacity_admission() const {
        return capacity_admission_;
    }

  private:
    protocol::BaseProverOptions proof_options_;
    protocol::BaseServerCapacityCaps capacity_caps_;
    protocol::BaseServerCapacityComponents capacity_components_;
    protocol::BaseServerCapacityAdmission capacity_admission_;
};

/// One-use client entropy for a fresh delegation session identifier. Construct
/// it from at least 256 CSPRNG bits with `make_base_client_nonce`.
class BaseClientNonce {
  public:
    BaseClientNonce(const BaseClientNonce &) = delete;
    BaseClientNonce &operator=(const BaseClientNonce &) = delete;
    BaseClientNonce(BaseClientNonce &&other) noexcept
        : bytes_(std::exchange(other.bytes_, Digest{})) {}
    BaseClientNonce &operator=(BaseClientNonce &&other) noexcept {
        bytes_ = std::exchange(other.bytes_, Digest{});
        return *this;
    }

  private:
    explicit BaseClientNonce(Digest value) : bytes_(value) {}

    Digest bytes_{};

    friend BaseClientNonce
    make_base_client_nonce(std::span<const std::uint8_t> random_bytes);
    friend struct base_client_detail::ClientStateAccess;
};

/// Client-private state retained while the server evaluates and proves. The
/// request commitment fixes the encrypted-input half of the Fiat--Shamir
/// statement without retaining a second ciphertext batch.
class BaseClientAwaitingResponse {
  public:
    BaseClientAwaitingResponse(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request_commitment, std::vector<fhe::SlotVector> inputs)
        : setup_id_(setup), session_id_(session), circuit_id_(circuit),
          trace_id_(trace), request_commitment_(request_commitment),
          input_layer_(std::move(inputs)) {}
    BaseClientAwaitingResponse(const BaseClientAwaitingResponse &) = delete;
    BaseClientAwaitingResponse &
    operator=(const BaseClientAwaitingResponse &) = delete;
    BaseClientAwaitingResponse(BaseClientAwaitingResponse &&other) noexcept
        : setup_id_(std::exchange(other.setup_id_, Digest{})),
          session_id_(std::exchange(other.session_id_, Digest{})),
          circuit_id_(std::exchange(other.circuit_id_, Digest{})),
          trace_id_(std::exchange(other.trace_id_, Digest{})),
          request_commitment_(
              std::exchange(other.request_commitment_, Digest{})),
          input_layer_(std::move(other.input_layer_)) {}
    BaseClientAwaitingResponse &
    operator=(BaseClientAwaitingResponse &&other) noexcept {
        setup_id_ = std::exchange(other.setup_id_, Digest{});
        session_id_ = std::exchange(other.session_id_, Digest{});
        circuit_id_ = std::exchange(other.circuit_id_, Digest{});
        trace_id_ = std::exchange(other.trace_id_, Digest{});
        request_commitment_ =
            std::exchange(other.request_commitment_, Digest{});
        input_layer_ = std::move(other.input_layer_);
        return *this;
    }

  private:
    Digest setup_id_{};
    Digest session_id_{};
    Digest circuit_id_{};
    Digest trace_id_{};
    Digest request_commitment_{};
    std::vector<fhe::SlotVector> input_layer_;

    friend struct base_client_detail::ClientStateAccess;
};

/// Client-private state after the sole response has been bound and decrypted.
/// It deliberately exposes no plaintext access: only successful proof
/// verification releases the payload outputs.
class BaseClientOpenedResponse {
  public:
    BaseClientOpenedResponse(const BaseClientOpenedResponse &) = delete;
    BaseClientOpenedResponse &
    operator=(const BaseClientOpenedResponse &) = delete;
    BaseClientOpenedResponse(BaseClientOpenedResponse &&other) noexcept
        : setup_id_(std::exchange(other.setup_id_, Digest{})),
          session_id_(std::exchange(other.session_id_, Digest{})),
          circuit_id_(std::exchange(other.circuit_id_, Digest{})),
          trace_id_(std::exchange(other.trace_id_, Digest{})),
          request_commitment_(
              std::exchange(other.request_commitment_, Digest{})),
          statement_digest_(
              std::exchange(other.statement_digest_, Digest{})),
          input_layer_(std::move(other.input_layer_)),
          output_layer_(std::move(other.output_layer_)),
          output_claim_(std::move(other.output_claim_)) {}
    BaseClientOpenedResponse &
    operator=(BaseClientOpenedResponse &&other) noexcept {
        setup_id_ = std::exchange(other.setup_id_, Digest{});
        session_id_ = std::exchange(other.session_id_, Digest{});
        circuit_id_ = std::exchange(other.circuit_id_, Digest{});
        trace_id_ = std::exchange(other.trace_id_, Digest{});
        request_commitment_ =
            std::exchange(other.request_commitment_, Digest{});
        statement_digest_ =
            std::exchange(other.statement_digest_, Digest{});
        input_layer_ = std::move(other.input_layer_);
        output_layer_ = std::move(other.output_layer_);
        output_claim_ = std::move(other.output_claim_);
        return *this;
    }

  private:
    BaseClientOpenedResponse(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request_commitment, Digest statement_digest,
        std::vector<fhe::SlotVector> inputs,
        std::vector<fhe::SlotVector> outputs,
        gkr::SingleClaim output_claim)
        : setup_id_(setup), session_id_(session), circuit_id_(circuit),
          trace_id_(trace), request_commitment_(request_commitment),
          statement_digest_(statement_digest),
          input_layer_(std::move(inputs)),
          output_layer_(std::move(outputs)),
          output_claim_(std::move(output_claim)) {}

    Digest setup_id_{};
    Digest session_id_{};
    Digest circuit_id_{};
    Digest trace_id_{};
    Digest request_commitment_{};
    Digest statement_digest_{};
    std::vector<fhe::SlotVector> input_layer_;
    std::vector<fhe::SlotVector> output_layer_;
    gkr::SingleClaim output_claim_;

    friend struct base_client_detail::ClientStateAccess;
};

/// In-process Base server state backed by compact Wide checkpoints. It is
/// move-only and not restartable: the evaluation context and circuit supplied
/// during publication must outlive this state. Once proving retires layer
/// zero, any failure is terminal and this state cannot be retried. Its stored
/// statement digest binds the separately owned output batch.
template <fhe::PersistableFheBackend Backend>
class CheckpointReplayBaseServerEvaluated {
  public:
    CheckpointReplayBaseServerEvaluated(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request_commitment, Digest statement_digest,
        payload::PayloadCheckpointReplayTrace<Backend> replay_trace,
        CheckpointReplayBaseServerResources resources)
        : setup_id_(setup), session_id_(session), circuit_id_(circuit),
          trace_id_(trace), request_commitment_(request_commitment),
          statement_digest_(statement_digest),
          trace_(std::move(replay_trace)),
          resources_(std::move(resources)) {}
    CheckpointReplayBaseServerEvaluated(
        const CheckpointReplayBaseServerEvaluated &) = delete;
    CheckpointReplayBaseServerEvaluated &operator=(
        const CheckpointReplayBaseServerEvaluated &) = delete;
    CheckpointReplayBaseServerEvaluated(
        CheckpointReplayBaseServerEvaluated &&) noexcept = default;
    CheckpointReplayBaseServerEvaluated &operator=(
        CheckpointReplayBaseServerEvaluated &&) noexcept = default;

    const CheckpointReplayBaseServerResources &resources() const {
        return resources_;
    }

  private:
    Digest setup_id_{};
    Digest session_id_{};
    Digest circuit_id_{};
    Digest trace_id_{};
    Digest request_commitment_{};
    Digest statement_digest_{};
    payload::PayloadCheckpointReplayTrace<Backend> trace_;
    CheckpointReplayBaseServerResources resources_;

    template <fhe::FheBackend B>
    friend struct BaseServerStateAccess;
};

template <fhe::FheBackend Backend> struct BaseClientRequestStart {
    BaseRequest<Backend> request;
    BaseClientAwaitingResponse state;
};

template <fhe::PersistableFheBackend Backend>
struct CheckpointReplayBaseServerEvaluationResult {
    BaseFheOutput<Backend> output;
    CheckpointReplayBaseServerEvaluated<Backend> state;
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_SESSION_STATE_HPP
