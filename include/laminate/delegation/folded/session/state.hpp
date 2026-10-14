#ifndef LAMINATE_DELEGATION_FOLDED_STATE_HPP
#define LAMINATE_DELEGATION_FOLDED_STATE_HPP

/// @file state.hpp
/// @brief Move-only client and server states for Folded delegation.

#include "laminate/delegation/folded/transport/messages.hpp"
#include "laminate/gkr/detail/folded/prover.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/protocol/packed/setup.hpp"
#include "laminate/protocol/storage/checkpoint_replay.hpp"
#include "laminate/protocol/packed/external/transcript_packing.hpp"

#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::protocol {
class PackedExternalProverSetup;
}

namespace laminate::delegation {

namespace folded_client_detail {
struct ClientStateAccess;
}

/// Evaluation-time Folded proof resources fixed before payload FHE begins.
/// Heavy immutable setup state remains shared through its internal handles;
/// callers receive only const access after construction.
class CheckpointReplayFoldedServerResources {
  public:
    CheckpointReplayFoldedServerResources(
        const protocol::FoldedSetup &packing_setup,
        gkr::folded_detail::IrreversibleFileFoldedGkrOptions
            proof_options,
        protocol::CheckpointReplayServerStorageLimits storage_limits,
        protocol::CheckpointReplayServerStorageAdmission admission)
        : packing_setup_(packing_setup),
          proof_options_(std::move(proof_options)),
          storage_limits_(std::move(storage_limits)),
          admission_(std::move(admission)) {}

    CheckpointReplayFoldedServerResources(
        const protocol::PackedExternalProverSetup &external_packing_setup,
        Digest external_packing_setup_identity,
        protocol::TranscriptPackingExternalAdmission packing_admission,
        gkr::folded_detail::IrreversibleFileFoldedGkrOptions
            proof_options,
        protocol::CheckpointReplayServerStorageLimits storage_limits,
        protocol::CheckpointReplayServerStorageAdmission admission)
        : external_packing_setup_identity_(
              external_packing_setup_identity),
          external_packing_setup_(&external_packing_setup),
          external_packing_admission_(std::move(packing_admission)),
          proof_options_(std::move(proof_options)),
          storage_limits_(std::move(storage_limits)),
          admission_(std::move(admission)) {
        if (external_packing_setup_identity == Digest{}) {
            throw std::invalid_argument(
                "external Folded packing setup identity is zero");
        }
    }

    const protocol::FoldedSetup &packing_setup() const {
        if (!packing_setup_) {
            throw std::logic_error(
                "checkpoint resources use external Folded packing");
        }
        return *packing_setup_;
    }
    bool uses_external_packing() const noexcept {
        return external_packing_setup_identity_.has_value();
    }
    bool matches_external_packing_setup(
        const protocol::PackedExternalProverSetup &setup) const noexcept {
        return external_packing_setup_ == &setup;
    }
    const Digest &external_packing_setup_identity() const {
        if (!external_packing_setup_identity_) {
            throw std::logic_error(
                "checkpoint resources use resident Folded packing");
        }
        return *external_packing_setup_identity_;
    }
    protocol::TranscriptPackingExternalAdmission
    take_external_packing_admission() {
        if (!external_packing_admission_) {
            throw std::logic_error(
                "external Folded packing admission is unavailable");
        }
        protocol::TranscriptPackingExternalAdmission result =
            std::move(*external_packing_admission_);
        external_packing_admission_.reset();
        return result;
    }
    const gkr::folded_detail::
        IrreversibleFileFoldedGkrOptions &
    proof_options() const {
        return proof_options_;
    }
    const protocol::CheckpointReplayServerStorageLimits &
    storage_limits() const {
        return storage_limits_;
    }
    const protocol::CheckpointReplayServerStorageAdmission &
    admission() const {
        return admission_;
    }

  private:
    std::optional<protocol::FoldedSetup> packing_setup_;
    std::optional<Digest> external_packing_setup_identity_;
    const protocol::PackedExternalProverSetup *external_packing_setup_ =
        nullptr;
    std::optional<protocol::TranscriptPackingExternalAdmission>
        external_packing_admission_;
    gkr::folded_detail::IrreversibleFileFoldedGkrOptions
        proof_options_;
    protocol::CheckpointReplayServerStorageLimits storage_limits_;
    protocol::CheckpointReplayServerStorageAdmission admission_;
};

/// One-use client entropy for a Folded delegation session.
class FoldedClientNonce {
  public:
    FoldedClientNonce(const FoldedClientNonce &) = delete;
    FoldedClientNonce &operator=(const FoldedClientNonce &) = delete;
    FoldedClientNonce(FoldedClientNonce &&other) noexcept
        : bytes_(std::exchange(other.bytes_, Digest{})) {}
    FoldedClientNonce &operator=(FoldedClientNonce &&other) noexcept {
        bytes_ = std::exchange(other.bytes_, Digest{});
        return *this;
    }

  private:
    explicit FoldedClientNonce(Digest value) : bytes_(value) {}
    Digest bytes_{};

    friend FoldedClientNonce
    make_folded_client_nonce(std::span<const std::uint8_t> random_bytes);
    friend struct folded_client_detail::ClientStateAccess;
};

/// Client-private state retained after publishing the sole request.
class FoldedClientAwaitingResponse {
  public:
    FoldedClientAwaitingResponse(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request_commitment, std::vector<fhe::SlotVector> inputs)
        : setup_id_(setup), session_id_(session), circuit_id_(circuit),
          trace_id_(trace), request_commitment_(request_commitment),
          input_layer_(std::move(inputs)) {}
    FoldedClientAwaitingResponse(const FoldedClientAwaitingResponse &) =
        delete;
    FoldedClientAwaitingResponse &
    operator=(const FoldedClientAwaitingResponse &) = delete;
    FoldedClientAwaitingResponse(
        FoldedClientAwaitingResponse &&other) noexcept
        : setup_id_(std::exchange(other.setup_id_, Digest{})),
          session_id_(std::exchange(other.session_id_, Digest{})),
          circuit_id_(std::exchange(other.circuit_id_, Digest{})),
          trace_id_(std::exchange(other.trace_id_, Digest{})),
          request_commitment_(
              std::exchange(other.request_commitment_, Digest{})),
          input_layer_(std::move(other.input_layer_)) {}
    FoldedClientAwaitingResponse &
    operator=(FoldedClientAwaitingResponse &&other) noexcept {
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
    friend struct folded_client_detail::ClientStateAccess;
};

/// Opaque tentative plaintext state. No output accessor exists; only the
/// successful verification transition can move out its plaintext values.
class FoldedClientOpenedResponse {
  public:
    FoldedClientOpenedResponse(const FoldedClientOpenedResponse &) = delete;
    FoldedClientOpenedResponse &
    operator=(const FoldedClientOpenedResponse &) = delete;
    FoldedClientOpenedResponse(
        FoldedClientOpenedResponse &&other) noexcept
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
    FoldedClientOpenedResponse &
    operator=(FoldedClientOpenedResponse &&other) noexcept {
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
    FoldedClientOpenedResponse(
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
    friend struct folded_client_detail::ClientStateAccess;
};

template <fhe::FheBackend Backend> struct FoldedServerReadyToProve {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    Digest request_commitment{};
    Digest statement_digest{};
    std::shared_ptr<const payload::EncryptedTrace<Backend>> trace;

    FoldedServerReadyToProve() = default;
    FoldedServerReadyToProve(
        Digest setup, Digest session, Digest circuit, Digest trace_identifier,
        Digest request, Digest statement,
        std::shared_ptr<const payload::EncryptedTrace<Backend>> encrypted_trace)
        : setup_id(setup), session_id(session), circuit_id(circuit),
          trace_id(trace_identifier), request_commitment(request),
          statement_digest(statement), trace(std::move(encrypted_trace)) {}
    FoldedServerReadyToProve(const FoldedServerReadyToProve &) = delete;
    FoldedServerReadyToProve &
    operator=(const FoldedServerReadyToProve &) = delete;
    FoldedServerReadyToProve(FoldedServerReadyToProve &&) noexcept = default;
    FoldedServerReadyToProve &
    operator=(FoldedServerReadyToProve &&) noexcept = default;
};

struct FileFoldedServerReadyToProve {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    Digest request_commitment{};
    Digest statement_digest{};
    payload::FileTraceStoreWriteResult trace_store;

    FileFoldedServerReadyToProve() = default;
    FileFoldedServerReadyToProve(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request, Digest statement,
        payload::FileTraceStoreWriteResult stored_trace)
        : setup_id(setup), session_id(session), circuit_id(circuit),
          trace_id(trace), request_commitment(request),
          statement_digest(statement), trace_store(std::move(stored_trace)) {}
    FileFoldedServerReadyToProve(const FileFoldedServerReadyToProve &) =
        delete;
    FileFoldedServerReadyToProve &
    operator=(const FileFoldedServerReadyToProve &) = delete;
    FileFoldedServerReadyToProve(
        FileFoldedServerReadyToProve &&) noexcept = default;
    FileFoldedServerReadyToProve &
    operator=(FileFoldedServerReadyToProve &&) noexcept = default;
};

template <fhe::PersistableFheBackend Backend>
struct CheckpointReplayFoldedServerReadyToProve {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    Digest request_commitment{};
    Digest statement_digest{};
    payload::PayloadCheckpointReplayTrace<Backend> trace;

    CheckpointReplayFoldedServerReadyToProve(
        Digest setup, Digest session, Digest circuit,
        Digest trace_identifier, Digest request, Digest statement,
        payload::PayloadCheckpointReplayTrace<Backend> replay_trace,
        CheckpointReplayFoldedServerResources admitted_resources)
        : setup_id(setup), session_id(session), circuit_id(circuit),
          trace_id(trace_identifier), request_commitment(request),
          statement_digest(statement), trace(std::move(replay_trace)),
          resources_(std::move(admitted_resources)) {}

    const CheckpointReplayFoldedServerResources &resources() const {
        return resources_;
    }
    CheckpointReplayFoldedServerResources &resources() {
        return resources_;
    }
    CheckpointReplayFoldedServerReadyToProve(
        const CheckpointReplayFoldedServerReadyToProve &) = delete;
    CheckpointReplayFoldedServerReadyToProve &
    operator=(const CheckpointReplayFoldedServerReadyToProve &) = delete;
    CheckpointReplayFoldedServerReadyToProve(
        CheckpointReplayFoldedServerReadyToProve &&) noexcept = default;
    CheckpointReplayFoldedServerReadyToProve &
    operator=(CheckpointReplayFoldedServerReadyToProve &&) noexcept =
        default;

  private:
    CheckpointReplayFoldedServerResources resources_;
};

template <fhe::FheBackend Backend> struct FoldedClientRequestStart {
    FoldedEvaluationRequest<Backend> request;
    FoldedClientAwaitingResponse state;
};

template <fhe::FheBackend Backend> struct FoldedServerEvaluationResult {
    FoldedFheOutput<Backend> output;
    FoldedServerReadyToProve<Backend> state;
};

template <fhe::PersistableFheBackend Backend>
struct FileFoldedServerEvaluationResult {
    FoldedFheOutput<Backend> output;
    FileFoldedServerReadyToProve state;
};

template <fhe::PersistableFheBackend Backend>
struct CheckpointReplayFoldedServerEvaluationResult {
    FoldedFheOutput<Backend> output;
    CheckpointReplayFoldedServerReadyToProve<Backend> state;
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_FOLDED_STATE_HPP
