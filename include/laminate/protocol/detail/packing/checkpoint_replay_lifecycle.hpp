#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_CHECKPOINT_REPLAY_LIFECYCLE_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_CHECKPOINT_REPLAY_LIFECYCLE_HPP

/// @file checkpoint_replay_lifecycle.hpp
/// @brief No-retry ownership checks shared by packed checkpoint provers.

#include "laminate/payload/checkpoint/session_engine.hpp"

#include <stdexcept>
#include <string>
#include <string_view>

namespace laminate::protocol::detail {

template <typename Options>
void require_irreversible_checkpoint_options(
    const Options &options, std::string_view operation) {
    if (options.lifecycle !=
            payload::FileTraceSessionLifecycle::IrreversibleNoRetry ||
        !options.reclaim_completed_multiplication_scratch) {
        throw std::invalid_argument(
            std::string(operation) +
            ": explicit IrreversibleNoRetry lifecycle and completed "
            "multiplication-scratch reclamation are required");
    }
}

template <typename Backend>
void require_fresh_checkpoint_replay(
    const payload::PayloadCheckpointReplayTrace<Backend> &trace,
    std::string_view variant) {
    if (!trace.report().checkpoint_set_published ||
        trace.proof_attempt_started() ||
        trace.report().all_payload_artifacts_retired) {
        throw std::invalid_argument(
            std::string(variant) +
            " checkpoint replay trace is not a fresh, unattempted "
            "published session");
    }
}

template <typename Backend>
void require_retired_checkpoint_replay(
    const payload::PayloadCheckpointReplayTrace<Backend> &trace,
    std::string_view variant) {
    if (!trace.report().all_payload_artifacts_retired ||
        trace.report().live_physical_bytes != 0) {
        throw std::logic_error(
            std::string(variant) +
            " checkpoint replay GKR did not retire every payload artifact");
    }
}

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_CHECKPOINT_REPLAY_LIFECYCLE_HPP
