#ifndef LAMINATE_DELEGATION_LANED_STATE_HPP
#define LAMINATE_DELEGATION_LANED_STATE_HPP

/// @file state.hpp
/// @brief Retained client and server state between delegation messages.

#include "laminate/delegation/laned/transport/messages.hpp"
#include "laminate/gkr/detail/laned/prover.hpp"
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

namespace laned_client_detail {
struct ClientStateAccess;
}

/// Evaluation-time storage contract retained unchanged until proving. The
/// setup is shallow-copied: mutable wrapper values are private to this state,
/// while heavyweight preprocessing remains shared through `shared_ptr<const>`.
/// Proof paths are normalized before construction, and only const access is
/// exposed so no online message can replace the admitted resources.
class CheckpointReplayLanedServerResources {
  public:
    CheckpointReplayLanedServerResources(
        const protocol::LanedSetup &packing_setup,
        gkr::laned_detail::IrreversibleFileLanedGkrOptions proof_options,
        protocol::CheckpointReplayServerStorageLimits storage_limits,
        protocol::CheckpointReplayServerStorageAdmission admission)
        : packing_setup_(packing_setup),
          proof_options_(std::move(proof_options)),
          storage_limits_(std::move(storage_limits)),
          admission_(std::move(admission)) {}

    CheckpointReplayLanedServerResources(
        const protocol::PackedExternalProverSetup &external_packing_setup,
        Digest external_packing_setup_identity,
        protocol::TranscriptPackingExternalAdmission packing_admission,
        gkr::laned_detail::IrreversibleFileLanedGkrOptions proof_options,
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
                "external Laned packing setup identity is zero");
        }
    }

    const protocol::LanedSetup &packing_setup() const {
        if (!packing_setup_) {
            throw std::logic_error(
                "checkpoint resources use external Laned packing");
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
                "checkpoint resources use resident Laned packing");
        }
        return *external_packing_setup_identity_;
    }
    protocol::TranscriptPackingExternalAdmission
    take_external_packing_admission() {
        if (!external_packing_admission_) {
            throw std::logic_error(
                "external Laned packing admission is unavailable");
        }
        protocol::TranscriptPackingExternalAdmission result =
            std::move(*external_packing_admission_);
        external_packing_admission_.reset();
        return result;
    }

    const gkr::laned_detail::IrreversibleFileLanedGkrOptions &
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
    std::optional<protocol::LanedSetup> packing_setup_;
    std::optional<Digest> external_packing_setup_identity_;
    const protocol::PackedExternalProverSetup *external_packing_setup_ =
        nullptr;
    std::optional<protocol::TranscriptPackingExternalAdmission>
        external_packing_admission_;
    gkr::laned_detail::IrreversibleFileLanedGkrOptions proof_options_;
    protocol::CheckpointReplayServerStorageLimits storage_limits_;
    protocol::CheckpointReplayServerStorageAdmission admission_;
};

/// One-use client entropy for the output-opening point. Construct it with
/// `make_laned_client_nonce` from at least 256 bits supplied by a CSPRNG.
class LanedClientNonce {
  public:
    LanedClientNonce(const LanedClientNonce &) = delete;
    LanedClientNonce &operator=(const LanedClientNonce &) = delete;
    LanedClientNonce(LanedClientNonce &&other) noexcept
        : bytes_(std::exchange(other.bytes_, Digest{})) {}
    LanedClientNonce &operator=(LanedClientNonce &&other) noexcept {
        bytes_ = std::exchange(other.bytes_, Digest{});
        return *this;
    }

  private:
    explicit LanedClientNonce(Digest value) : bytes_(value) {}

    Digest bytes_{};

    friend LanedClientNonce
    make_laned_client_nonce(std::span<const std::uint8_t> random_bytes);
    friend struct laned_client_detail::ClientStateAccess;
};

/// Client-private state retained while the server evaluates and proves. The
/// request commitment fixes the encrypted-input half of the statement without
/// retaining a second ciphertext batch.
class LanedClientAwaitingResponse {
  public:
    LanedClientAwaitingResponse(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request_commitment, std::vector<fhe::SlotVector> inputs)
        : setup_id_(setup), session_id_(session), circuit_id_(circuit),
          trace_id_(trace), request_commitment_(request_commitment),
          input_layer_(std::move(inputs)) {}
    LanedClientAwaitingResponse(const LanedClientAwaitingResponse &) = delete;
    LanedClientAwaitingResponse &
    operator=(const LanedClientAwaitingResponse &) = delete;
    LanedClientAwaitingResponse(
        LanedClientAwaitingResponse &&other) noexcept
        : setup_id_(std::exchange(other.setup_id_, Digest{})),
          session_id_(std::exchange(other.session_id_, Digest{})),
          circuit_id_(std::exchange(other.circuit_id_, Digest{})),
          trace_id_(std::exchange(other.trace_id_, Digest{})),
          request_commitment_(
              std::exchange(other.request_commitment_, Digest{})),
          input_layer_(std::move(other.input_layer_)) {}
    LanedClientAwaitingResponse &
    operator=(LanedClientAwaitingResponse &&other) noexcept {
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
    friend struct laned_client_detail::ClientStateAccess;
};

/// Client-private state after binding and decrypting the sole response. It
/// deliberately exposes no plaintext output; only successful verification can
/// release the tentative values.
class LanedClientOpenedResponse {
  public:
    LanedClientOpenedResponse(const LanedClientOpenedResponse &) = delete;
    LanedClientOpenedResponse &
    operator=(const LanedClientOpenedResponse &) = delete;
    LanedClientOpenedResponse(
        LanedClientOpenedResponse &&other) noexcept
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
    LanedClientOpenedResponse &
    operator=(LanedClientOpenedResponse &&other) noexcept {
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
    LanedClientOpenedResponse(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request_commitment, Digest statement_digest,
        std::vector<fhe::SlotVector> inputs,
        std::vector<fhe::SlotVector> output_layer,
        gkr::SingleClaim output_claim)
        : setup_id_(setup), session_id_(session), circuit_id_(circuit),
          trace_id_(trace), request_commitment_(request_commitment),
          statement_digest_(statement_digest),
          input_layer_(std::move(inputs)),
          output_layer_(std::move(output_layer)),
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
    friend struct laned_client_detail::ClientStateAccess;
};

/// Server-private state retained after payload evaluation and consumed by the
/// one-shot proof transition. The request commitment and statement digest bind
/// the exact output carried beside this state.
template <fhe::FheBackend Backend> struct LanedServerReadyToProve {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    Digest request_commitment{};
    Digest statement_digest{};
    std::shared_ptr<const payload::EncryptedTrace<Backend>> trace;

    LanedServerReadyToProve() = default;
    LanedServerReadyToProve(
        Digest setup, Digest session, Digest circuit, Digest trace_identifier,
        Digest request, Digest statement,
        std::shared_ptr<const payload::EncryptedTrace<Backend>> encrypted_trace)
        : setup_id(setup), session_id(session), circuit_id(circuit),
          trace_id(trace_identifier), request_commitment(request),
          statement_digest(statement), trace(std::move(encrypted_trace)) {}
    LanedServerReadyToProve(const LanedServerReadyToProve &) = delete;
    LanedServerReadyToProve &
    operator=(const LanedServerReadyToProve &) = delete;
    LanedServerReadyToProve(LanedServerReadyToProve &&) noexcept = default;
    LanedServerReadyToProve &
    operator=(LanedServerReadyToProve &&) noexcept = default;
};

/// Server-private state whose encrypted trace is file-backed rather than
/// resident. This is the natural handoff between evaluation and proving: the
/// evaluation result owns the bounded output batch while this state names and
/// binds the private trace store. Reopening requires the store to remain
/// private and unchanged; FileTraceStore does not promise power-loss durability.
struct FileLanedServerReadyToProve {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    Digest request_commitment{};
    Digest statement_digest{};
    payload::FileTraceStoreWriteResult trace_store;

    FileLanedServerReadyToProve() = default;
    FileLanedServerReadyToProve(
        Digest setup, Digest session, Digest circuit, Digest trace,
        Digest request, Digest statement,
        payload::FileTraceStoreWriteResult stored_trace)
        : setup_id(setup), session_id(session), circuit_id(circuit),
          trace_id(trace), request_commitment(request),
          statement_digest(statement), trace_store(std::move(stored_trace)) {}
    FileLanedServerReadyToProve(
        const FileLanedServerReadyToProve &) = delete;
    FileLanedServerReadyToProve &operator=(
        const FileLanedServerReadyToProve &) = delete;
    FileLanedServerReadyToProve(
        FileLanedServerReadyToProve &&) noexcept = default;
    FileLanedServerReadyToProve &operator=(
        FileLanedServerReadyToProve &&) noexcept = default;
};

/// Server-private state for sparse checkpoint replay. Unlike the reopenable
/// full-trace handoff, this state owns live backend-bound readers and replay
/// bookkeeping in-process. It is move-only, one-shot, and not crash-resumable.
/// The exact evaluation context and layered-circuit objects supplied during
/// evaluation must outlive this state and its proof transition; the state
/// cannot be reopened, rebound, or transferred to another process. Once its
/// trace reports `proof_attempt_started()`, the state is terminal even if the
/// proof call threw before final artifact retirement.
template <fhe::PersistableFheBackend Backend>
struct CheckpointReplayLanedServerReadyToProve {
    Digest setup_id{};
    Digest session_id{};
    Digest circuit_id{};
    Digest trace_id{};
    Digest request_commitment{};
    Digest statement_digest{};
    payload::PayloadCheckpointReplayTrace<Backend> trace;

    CheckpointReplayLanedServerReadyToProve(
        Digest setup, Digest session, Digest circuit, Digest trace_identifier,
        Digest request, Digest statement,
        payload::PayloadCheckpointReplayTrace<Backend> replay_trace,
        CheckpointReplayLanedServerResources admitted_resources)
        : setup_id(setup), session_id(session), circuit_id(circuit),
          trace_id(trace_identifier), request_commitment(request),
          statement_digest(statement), trace(std::move(replay_trace)),
          resources_(std::move(admitted_resources)) {}

    const CheckpointReplayLanedServerResources &resources() const {
        return resources_;
    }
    CheckpointReplayLanedServerResources &resources() {
        return resources_;
    }
    CheckpointReplayLanedServerReadyToProve(
        const CheckpointReplayLanedServerReadyToProve &) = delete;
    CheckpointReplayLanedServerReadyToProve &operator=(
        const CheckpointReplayLanedServerReadyToProve &) = delete;
    CheckpointReplayLanedServerReadyToProve(
        CheckpointReplayLanedServerReadyToProve &&) noexcept = default;
    CheckpointReplayLanedServerReadyToProve &operator=(
        CheckpointReplayLanedServerReadyToProve &&) noexcept = default;

  private:
    CheckpointReplayLanedServerResources resources_;
};

template <fhe::FheBackend Backend> struct LanedClientRequestStart {
    LanedEvaluationRequest<Backend> request;
    LanedClientAwaitingResponse state;
};

template <fhe::FheBackend Backend> struct LanedServerEvaluationResult {
    LanedFheOutput<Backend> output;
    LanedServerReadyToProve<Backend> state;
};

template <fhe::PersistableFheBackend Backend>
struct FileLanedServerEvaluationResult {
    LanedFheOutput<Backend> output;
    FileLanedServerReadyToProve state;
};

template <fhe::PersistableFheBackend Backend>
struct CheckpointReplayLanedServerEvaluationResult {
    /// The exact encrypted output is retained until it can be published in
    /// the same immutable response as the proof.
    LanedFheOutput<Backend> output;
    CheckpointReplayLanedServerReadyToProve<Backend> state;
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_LANED_STATE_HPP
