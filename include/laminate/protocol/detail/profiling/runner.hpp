#ifndef LAMINATE_PROTOCOL_DETAIL_PROFILING_RUNNER_HPP
#define LAMINATE_PROTOCOL_DETAIL_PROFILING_RUNNER_HPP

/// @file runner.hpp
/// @brief Timing adapters for the incremental protocol drivers.

#include "laminate/protocol/detail/profiling/clock.hpp"
#include "laminate/protocol/metrics/types.hpp"
#include "laminate/verification_profile.hpp"

#include <stdexcept>
#include <utility>

namespace laminate::protocol::profiling_detail {

/// Public challenge reconstruction and recovered-message arithmetic execute
/// at different times in the packed verifier. Keep their per-layer diagnostic
/// totals together without charging the already verified gate PCS twice.
inline void add_packed_plaintext_timings(
    BaseVerifierTimings &public_timings,
    const BaseVerifierTimings &plaintext_timings) {
    if (plaintext_timings.layers.size() > public_timings.layers.size()) {
        throw std::logic_error("packed verifier timing layer mismatch");
    }
    for (std::size_t i = 0; i < plaintext_timings.layers.size(); ++i) {
        auto &combined = public_timings.layers[i];
        const auto &arithmetic = plaintext_timings.layers[i];
        if (combined.layer != arithmetic.layer || combined.kind != arithmetic.kind) {
            throw std::logic_error("packed verifier timing layer mismatch");
        }
        combined.wall_ms += arithmetic.wall_ms;
        combined.cpu_ms += arithmetic.cpu_ms;
    }
}

template <typename Prover, typename Timings>
auto run_prover(Prover &prover, Timings &timings) {
    auto state = prover.begin();
    timings.layers.reserve(state.proof.reductions.capacity());

    while (prover.has_next_layer(state)) {
        const std::size_t layer = state.next_layer;
        const payload::LayerKind kind = prover.next_layer_kind(state);
        const Stopwatch timer;
        prover.reduce_next_layer(state);
        const Elapsed elapsed = timer.stop();
        timings.layers.push_back(
            BaseLayerTiming{layer, kind, elapsed.wall_ms, elapsed.cpu_ms});
    }

    const Stopwatch gate_timer;
    prover.finish(state);
    const Elapsed gate_elapsed = gate_timer.stop();
    timings.gate_mle_opening_wall_ms = gate_elapsed.wall_ms;
    timings.gate_mle_opening_cpu_ms = gate_elapsed.cpu_ms;
    return std::move(state.proof);
}

template <typename Verifier, typename Timings>
bool run_verifier(Verifier &verifier, Timings &timings) {
    auto state = verifier.begin();
    if (!state) {
        return false;
    }

    while (verifier.has_next_layer(*state)) {
        const std::size_t layer = state->next_layer;
        const payload::LayerKind kind = verifier.next_layer_kind(*state);
        const Stopwatch timer;
        const bool accepted = verifier.verify_next_layer(*state);
        const Elapsed elapsed = timer.stop();
        timings.layers.push_back(
            BaseLayerTiming{layer, kind, elapsed.wall_ms, elapsed.cpu_ms});
        if (!accepted) {
            return false;
        }
    }

    const bool terminal = [&] {
        const verification_profile::ScopedVerificationPhase phase(
            verification_profile::Category::TerminalInputMLE);
        return verifier.terminal_claim_is_valid(*state);
    }();
    const Stopwatch gate_timer;
    const bool gate_opening = [&] {
        // Gate PCS, including its own Fiat--Shamir transcript, belongs to
        // plaintext GKR verification rather than ciphertext recovery.
        const verification_profile::ScopedVerificationPhase phase(
            verification_profile::Category::GkrPlaintext, false);
        return verifier.verify_gate_opening();
    }();
    const Elapsed gate_elapsed = gate_timer.stop();
    timings.gate_mle_opening_wall_ms = gate_elapsed.wall_ms;
    timings.gate_mle_opening_cpu_ms = gate_elapsed.cpu_ms;
    return terminal && gate_opening;
}

} // namespace laminate::protocol::profiling_detail

#endif // LAMINATE_PROTOCOL_DETAIL_PROFILING_RUNNER_HPP
