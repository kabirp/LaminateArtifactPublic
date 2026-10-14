#ifndef LAMINATE_DELEGATION_BASE_SERVER_STATE_ACCESS_HPP
#define LAMINATE_DELEGATION_BASE_SERVER_STATE_ACCESS_HPP

/// @file server/state_access.hpp
/// @brief Privileged access to move-only Base server state.

#include "laminate/delegation/base/session/state.hpp"

namespace laminate::delegation {

template <fhe::FheBackend Backend> struct BaseServerStateAccess {
    static const Digest &setup_id(
        const CheckpointReplayBaseServerEvaluated<Backend> &state)
        requires fhe::PersistableFheBackend<Backend>
    {
        return state.setup_id_;
    }
    static const Digest &session_id(
        const CheckpointReplayBaseServerEvaluated<Backend> &state)
        requires fhe::PersistableFheBackend<Backend>
    {
        return state.session_id_;
    }
    static const Digest &circuit_id(
        const CheckpointReplayBaseServerEvaluated<Backend> &state)
        requires fhe::PersistableFheBackend<Backend>
    {
        return state.circuit_id_;
    }
    static const Digest &trace_id(
        const CheckpointReplayBaseServerEvaluated<Backend> &state)
        requires fhe::PersistableFheBackend<Backend>
    {
        return state.trace_id_;
    }
    static payload::PayloadCheckpointReplayTrace<Backend> &trace(
        CheckpointReplayBaseServerEvaluated<Backend> &state)
        requires fhe::PersistableFheBackend<Backend>
    {
        return state.trace_;
    }
    static const payload::PayloadCheckpointReplayTrace<Backend> &trace(
        const CheckpointReplayBaseServerEvaluated<Backend> &state)
        requires fhe::PersistableFheBackend<Backend>
    {
        return state.trace_;
    }
    static const Digest &request_commitment(
        const CheckpointReplayBaseServerEvaluated<Backend> &state)
        requires fhe::PersistableFheBackend<Backend>
    {
        return state.request_commitment_;
    }
    static const Digest &statement_digest(
        const CheckpointReplayBaseServerEvaluated<Backend> &state)
        requires fhe::PersistableFheBackend<Backend>
    {
        return state.statement_digest_;
    }
};

} // namespace laminate::delegation

#endif // LAMINATE_DELEGATION_BASE_SERVER_STATE_ACCESS_HPP
