#ifndef LAMINATE_VERIFICATION_PROFILE_HPP
#define LAMINATE_VERIFICATION_PROFILE_HPP

/// @file verification_profile.hpp
/// @brief Opt-in, exclusive client verification timings. No clock is read
/// unless a session is active on the calling thread.

#include <array>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <optional>

namespace laminate::verification_profile {

enum class Category {
    Recovery,
    GkrPlaintext,
    TerminalInputMLE,
    PackingSNARK,
    WFNoise,
    OutputDecryption,
};

struct Elapsed {
    double wall_ms = 0;
    double cpu_ms = 0;

    Elapsed &operator+=(const Elapsed &other) {
        wall_ms += other.wall_ms;
        cpu_ms += other.cpu_ms;
        return *this;
    }
};

inline Elapsed operator+(Elapsed left, const Elapsed &right) {
    return left += right;
}

struct VerificationBreakdown {
    Elapsed recovery;
    Elapsed gkr_plaintext;
    Elapsed terminal_input_mle;
    Elapsed packing_snark;
    Elapsed wf_noise;
    Elapsed output_decryption;

    /// Diagnostic entry counts let tests check routing without clock thresholds.
    std::array<std::size_t, 6> entries{};

    std::size_t phase_entries(Category category) const {
        return entries[static_cast<std::size_t>(category)];
    }

    Elapsed gkr() const { return recovery + gkr_plaintext; }
    Elapsed vcoed() const {
        return gkr() + terminal_input_mle + packing_snark + wf_noise;
    }
    Elapsed total() const { return vcoed() + output_decryption; }

    VerificationBreakdown &operator+=(const VerificationBreakdown &other) {
        recovery += other.recovery;
        gkr_plaintext += other.gkr_plaintext;
        terminal_input_mle += other.terminal_input_mle;
        packing_snark += other.packing_snark;
        wf_noise += other.wf_noise;
        output_decryption += other.output_decryption;
        for (std::size_t index = 0; index < entries.size(); ++index) {
            entries[index] += other.entries[index];
        }
        return *this;
    }
};

namespace detail {

inline Elapsed &elapsed_for(VerificationBreakdown &breakdown,
                            Category category) {
    switch (category) {
    case Category::Recovery: return breakdown.recovery;
    case Category::GkrPlaintext: return breakdown.gkr_plaintext;
    case Category::TerminalInputMLE: return breakdown.terminal_input_mle;
    case Category::PackingSNARK: return breakdown.packing_snark;
    case Category::WFNoise: return breakdown.wf_noise;
    case Category::OutputDecryption: return breakdown.output_decryption;
    }
    return breakdown.gkr_plaintext;
}

struct Stamp {
    std::chrono::steady_clock::time_point wall;
    std::clock_t cpu;

    static Stamp now() {
        return {std::chrono::steady_clock::now(), std::clock()};
    }
};

struct SessionState {
    VerificationBreakdown &breakdown;
    Category category = Category::GkrPlaintext;
    bool allow_gkr_transcript_recovery = true;
    Stamp start{};

    void checkpoint(const Stamp &end) {
        elapsed_for(breakdown, category) += Elapsed{
            std::chrono::duration<double, std::milli>(end.wall - start.wall)
                .count(),
            1000.0 * static_cast<double>(end.cpu - start.cpu) /
                static_cast<double>(CLOCKS_PER_SEC)};
        start = end;
    }
};

inline thread_local SessionState *active_session = nullptr;

} // namespace detail

/// Add to an existing ledger; callers may separately scope response opening
/// and verification so I/O and preprocessing loads are never measured here.
/// Nested sessions pause the outer ledger and restore it on exit.
class ScopedVerificationSession {
  public:
    explicit ScopedVerificationSession(VerificationBreakdown &breakdown)
        : state_{breakdown}, previous_(detail::active_session) {
        const auto now = detail::Stamp::now();
        if (previous_) {
            previous_->checkpoint(now);
        }
        state_.start = now;
        ++breakdown.entries[static_cast<std::size_t>(state_.category)];
        detail::active_session = &state_;
    }

    ~ScopedVerificationSession() {
        const auto now = detail::Stamp::now();
        state_.checkpoint(now);
        detail::active_session = previous_;
        if (previous_) {
            previous_->start = now;
        }
    }

    ScopedVerificationSession(const ScopedVerificationSession &) = delete;
    ScopedVerificationSession &operator=(const ScopedVerificationSession &) =
        delete;

  private:
    detail::SessionState state_;
    detail::SessionState *previous_;
};

/// Exclude diagnostics or I/O from the current ledger. Callbacks see no
/// active session, but may independently profile their own work if desired.
class ScopedVerificationPause {
  public:
    ScopedVerificationPause() : previous_(detail::active_session) {
        if (!previous_) {
            return;
        }
        previous_->checkpoint(detail::Stamp::now());
        detail::active_session = nullptr;
    }

    ~ScopedVerificationPause() {
        if (!previous_) {
            return;
        }
        previous_->start = detail::Stamp::now();
        detail::active_session = previous_;
    }

    ScopedVerificationPause(const ScopedVerificationPause &) = delete;
    ScopedVerificationPause &operator=(const ScopedVerificationPause &) =
        delete;

  private:
    detail::SessionState *previous_;
};

/// Only the innermost scope accrues time. Setting the second argument false
/// keeps a subprotocol's own Fiat--Shamir work in its enclosing category.
class ScopedVerificationPhase {
  public:
    explicit ScopedVerificationPhase(
        Category category, bool allow_gkr_transcript_recovery = true)
        : state_(detail::active_session) {
        if (!state_) {
            return;
        }
        state_->checkpoint(detail::Stamp::now());
        previous_category_ = state_->category;
        previous_allow_recovery_ = state_->allow_gkr_transcript_recovery;
        state_->category = category;
        state_->allow_gkr_transcript_recovery =
            allow_gkr_transcript_recovery;
        ++state_->breakdown.entries[static_cast<std::size_t>(category)];
    }

    ~ScopedVerificationPhase() {
        if (!state_) {
            return;
        }
        state_->checkpoint(detail::Stamp::now());
        state_->category = previous_category_;
        state_->allow_gkr_transcript_recovery = previous_allow_recovery_;
    }

    ScopedVerificationPhase(const ScopedVerificationPhase &) = delete;
    ScopedVerificationPhase &operator=(const ScopedVerificationPhase &) =
        delete;

  private:
    detail::SessionState *state_;
    Category previous_category_ = Category::GkrPlaintext;
    bool previous_allow_recovery_ = true;
};

/// Transcript replay belongs to recovery only while processing GKR messages.
/// Packing SNARK, terminal MLE, and gate PCS keep their own transcript work.
class ScopedTranscriptRecovery {
  public:
    ScopedTranscriptRecovery() {
        const auto *state = detail::active_session;
        if (state && state->category == Category::GkrPlaintext &&
            state->allow_gkr_transcript_recovery) {
            phase_.emplace(Category::Recovery);
        }
    }

  private:
    std::optional<ScopedVerificationPhase> phase_;
};

} // namespace laminate::verification_profile

#endif // LAMINATE_VERIFICATION_PROFILE_HPP
