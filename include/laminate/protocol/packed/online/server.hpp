#ifndef LAMINATE_PROTOCOL_PACKED_ONLINE_SERVER_HPP
#define LAMINATE_PROTOCOL_PACKED_ONLINE_SERVER_HPP

/// @file server.hpp
/// @brief Authenticated Folded/Laned server state for recurring requests.

#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/protocol/packed/preprocessing/roles.hpp"
#include "laminate/setup/gate_mle.hpp"

#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

namespace laminate::protocol {

template <PackedRolePreprocessingBackend Backend>
class AuthenticatedPackedServerOnlineState;

template <PackedRolePreprocessingBackend Backend>
class OpenedPackedServerEvaluation;

template <PackedRolePreprocessingBackend Backend>
OpenedPackedServerEvaluation<Backend> open_packed_server_evaluation(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const Digest &expected_root_storage_identity,
    typename Backend::EvalContext evaluation_context,
    const PackedRolePreprocessingOpenLimits &limits,
    std::shared_ptr<const gates::GateTableProverKey>
        gate_mle_prover_key = {},
    const gates::GateTableBuildOptions &gate_options = {});

template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedServerOnlineState<Backend>
make_authenticated_packed_server_online_state(
    OpenedPackedServerEvaluation<Backend> opened,
    payload::FheEvaluationPlan evaluation_plan,
    payload::PayloadCheckpointReplayProblem replay_problem,
    payload::PayloadCheckpointReplayBudgets replay_budgets,
    payload::PayloadCheckpointReplayPlan replay_plan);

/// Heap-stable evaluation state paired with the authenticated packed-server
/// role that refers to its exact backend context. The two owners cannot be
/// separated before they are consumed by the authenticated online state.
template <PackedRolePreprocessingBackend Backend>
class OpenedPackedServerEvaluation {
  public:
    OpenedPackedServerEvaluation(const OpenedPackedServerEvaluation &) =
        delete;
    OpenedPackedServerEvaluation &operator=(
        const OpenedPackedServerEvaluation &) = delete;
    OpenedPackedServerEvaluation(
        OpenedPackedServerEvaluation &&) noexcept = default;
    OpenedPackedServerEvaluation &operator=(
        OpenedPackedServerEvaluation &&) = delete;

    typename Backend::EvalContext &evaluation_context() {
        return evaluation_->context;
    }
    const typename Backend::EvalContext &evaluation_context() const {
        return evaluation_->context;
    }
    const PublicSetup &public_setup() const {
        return evaluation_->public_setup;
    }
    const OpenedPackedServerRoleState<Backend> &role() const {
        return role_;
    }

  private:
    OpenedPackedServerEvaluation(
        std::unique_ptr<EvaluationSetup<Backend>> evaluation,
        OpenedPackedServerRoleState<Backend> role)
        : evaluation_(std::move(evaluation)), role_(std::move(role)) {}

    friend OpenedPackedServerEvaluation<Backend>
    open_packed_server_evaluation<Backend>(
        const std::filesystem::path &, const std::filesystem::path &,
        const Digest &, typename Backend::EvalContext,
        const PackedRolePreprocessingOpenLimits &,
        std::shared_ptr<const gates::GateTableProverKey>,
        const gates::GateTableBuildOptions &);

    friend AuthenticatedPackedServerOnlineState<Backend>
    make_authenticated_packed_server_online_state<Backend>(
        OpenedPackedServerEvaluation<Backend>,
        payload::FheEvaluationPlan,
        payload::PayloadCheckpointReplayProblem,
        payload::PayloadCheckpointReplayBudgets,
        payload::PayloadCheckpointReplayPlan);

    std::unique_ptr<EvaluationSetup<Backend>> evaluation_;
    OpenedPackedServerRoleState<Backend> role_;
};

/// Restore a server context whose public setup is owned by the authenticated
/// packed workload. The role is opened first without retaining a context
/// reference; the evaluation setup is then allocated at its final address
/// before the role is bound to that exact context.
template <PackedRolePreprocessingBackend Backend>
OpenedPackedServerEvaluation<Backend> open_packed_server_evaluation(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const Digest &expected_root_storage_identity,
    typename Backend::EvalContext evaluation_context,
    const PackedRolePreprocessingOpenLimits &limits,
    std::shared_ptr<const gates::GateTableProverKey>
        gate_mle_prover_key,
    const gates::GateTableBuildOptions &gate_options) {
    OpenedPackedServerRoleCore core =
        detail::open_packed_server_role_core(
            shared_directory, server_directory,
            expected_root_storage_identity,
            Backend::storage_context_id(evaluation_context), limits);
    if (!gate_mle_prover_key) {
        gate_mle_prover_key = restore_gate_mle_prover_key(
            core.publication.workload.circuit(),
            core.publication.workload.public_setup(), gate_options);
    }
    auto evaluation = std::make_unique<EvaluationSetup<Backend>>(
        make_evaluation_setup<Backend>(
            core.publication.workload.public_setup(),
            std::move(evaluation_context),
            std::move(gate_mle_prover_key)));
    auto role = detail::bind_packed_server_role_state<Backend>(
        std::move(core), evaluation->context);
    return OpenedPackedServerEvaluation<Backend>(
        std::move(evaluation), std::move(role));
}

template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedServerOnlineState<Backend>
make_authenticated_packed_server_online_state(
    std::unique_ptr<EvaluationSetup<Backend>> evaluation,
    OpenedPackedServerRoleState<Backend> opened,
    payload::FheEvaluationPlan evaluation_plan,
    payload::PayloadCheckpointReplayProblem replay_problem,
    payload::PayloadCheckpointReplayBudgets replay_budgets,
    payload::PayloadCheckpointReplayPlan replay_plan);

/// Complete immutable server authority restored before a request is timed.
///
/// The evaluation setup lives behind a stable allocation because the opened
/// external prover state binds that exact backend context. The checkpoint
/// certificate caches all circuit/layout/replay-plan validation, while the
/// online transitions continue to validate request ciphertexts, mutable
/// roots, storage availability, trace state, and proof retirement.
template <PackedRolePreprocessingBackend Backend>
class AuthenticatedPackedServerOnlineState {
  public:
    AuthenticatedPackedServerOnlineState(
        const AuthenticatedPackedServerOnlineState &) = delete;
    AuthenticatedPackedServerOnlineState &operator=(
        const AuthenticatedPackedServerOnlineState &) = delete;
    AuthenticatedPackedServerOnlineState(
        AuthenticatedPackedServerOnlineState &&) noexcept = default;
    AuthenticatedPackedServerOnlineState &operator=(
        AuthenticatedPackedServerOnlineState &&) noexcept = default;

    PackingGkrVariant variant() const noexcept {
        return state_->opened.core().role_static.variant;
    }
    const CertifiedPackedWorkloadStatic &workload() const {
        return state_->opened.workload();
    }
    const EvaluationSetup<Backend> &evaluation() const {
        return *state_->evaluation;
    }
    typename Backend::EvalContext &evaluation_context() {
        return state_->evaluation->context;
    }
    const typename Backend::EvalContext &evaluation_context() const {
        return state_->evaluation->context;
    }
    const PackedExternalProverSetup &prover_setup() const {
        return state_->opened.prover_setup();
    }
    const payload::CertifiedPayloadCheckpointReplayStatic &
    checkpoint_replay() const {
        return state_->checkpoint_replay;
    }
    const CertifiedPackedExternalGkrStatic<Backend> &gkr_static() const {
        return *state_->gkr_static;
    }
    const Digest &setup_id() const noexcept { return state_->setup_id; }
    const Digest &circuit_id() const noexcept { return state_->circuit_id; }

  private:
    struct State {
        State(
        std::unique_ptr<EvaluationSetup<Backend>> evaluation,
        OpenedPackedServerRoleState<Backend> opened,
        payload::CertifiedPayloadCheckpointReplayStatic checkpoint_replay,
        Digest setup_id, Digest circuit_id)
            : evaluation(std::move(evaluation)), opened(std::move(opened)),
              checkpoint_replay(std::move(checkpoint_replay)),
              setup_id(setup_id), circuit_id(circuit_id) {}

        std::unique_ptr<EvaluationSetup<Backend>> evaluation;
        OpenedPackedServerRoleState<Backend> opened;
        payload::CertifiedPayloadCheckpointReplayStatic checkpoint_replay;
        std::optional<CertifiedPackedExternalGkrStatic<Backend>> gkr_static;
        Digest setup_id{};
        Digest circuit_id{};
    };

    explicit AuthenticatedPackedServerOnlineState(
        std::unique_ptr<State> state)
        : state_(std::move(state)) {}

    friend AuthenticatedPackedServerOnlineState<Backend>
    make_authenticated_packed_server_online_state<Backend>(
        std::unique_ptr<EvaluationSetup<Backend>>,
        OpenedPackedServerRoleState<Backend>,
        payload::FheEvaluationPlan,
        payload::PayloadCheckpointReplayProblem,
        payload::PayloadCheckpointReplayBudgets,
        payload::PayloadCheckpointReplayPlan);

    std::unique_ptr<State> state_;
};

template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedServerOnlineState<Backend>
make_authenticated_packed_server_online_state(
    std::unique_ptr<EvaluationSetup<Backend>> evaluation,
    OpenedPackedServerRoleState<Backend> opened,
    payload::FheEvaluationPlan evaluation_plan,
    payload::PayloadCheckpointReplayProblem replay_problem,
    payload::PayloadCheckpointReplayBudgets replay_budgets,
    payload::PayloadCheckpointReplayPlan replay_plan) {
    if (!evaluation) {
        throw std::invalid_argument(
            "authenticated packed server needs an evaluation setup");
    }
    const CertifiedPackedWorkloadStatic &workload = opened.workload();
    if (&opened.evaluation_context() != &evaluation->context ||
        Backend::storage_context_id(evaluation->context) !=
            opened.core().role_static.fhe_context_storage_id ||
        Backend::slot_count(evaluation->context) !=
            workload.public_setup().shape.slot_count) {
        throw std::invalid_argument(
            "authenticated packed server context does not match its "
            "opened role");
    }
    evaluation->public_setup.validate(
        workload.payload(), workload.circuit());
    const Digest setup_id = setup_digest(evaluation->public_setup);
    const Digest circuit_id = evaluation->public_setup.circuit_digest;
    if (setup_id != workload.setup_digest() ||
        circuit_id != workload.circuit_digest()) {
        throw std::invalid_argument(
            "authenticated packed server public setup does not match its "
            "workload");
    }
    preflight_packed_external_prover_setup<Backend>(
        opened.core().role_static.variant, workload.payload(),
        workload.circuit(), *evaluation, opened.prover_setup());
    payload::CertifiedPayloadCheckpointReplayStatic checkpoint =
        payload::certify_payload_checkpoint_replay_static(
            workload.payload(),
            payload::derive_certified_canonical_trace_layout(
                workload.circuit()),
            std::move(evaluation_plan), std::move(replay_problem),
            std::move(replay_budgets), std::move(replay_plan));
    using Online = AuthenticatedPackedServerOnlineState<Backend>;
    auto state = std::make_unique<typename Online::State>(
        std::move(evaluation), std::move(opened), std::move(checkpoint),
        setup_id, circuit_id);
    state->gkr_static.emplace(certify_packed_external_gkr_static<Backend>(
        state->opened.core().role_static.variant,
        state->opened.workload().payload(),
        state->opened.workload().circuit(), *state->evaluation,
        state->opened.prover_setup(),
        state->checkpoint_replay.proof_trace_template()));
    return Online(std::move(state));
}

template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedServerOnlineState<Backend>
make_authenticated_packed_server_online_state(
    OpenedPackedServerEvaluation<Backend> opened,
    payload::FheEvaluationPlan evaluation_plan,
    payload::PayloadCheckpointReplayProblem replay_problem,
    payload::PayloadCheckpointReplayBudgets replay_budgets,
    payload::PayloadCheckpointReplayPlan replay_plan) {
    return make_authenticated_packed_server_online_state<Backend>(
        std::move(opened.evaluation_), std::move(opened.role_),
        std::move(evaluation_plan), std::move(replay_problem),
        std::move(replay_budgets), std::move(replay_plan));
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_ONLINE_SERVER_HPP
