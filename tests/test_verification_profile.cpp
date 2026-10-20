#include "test_helpers.hpp"

#include "laminate/transcript/transcript.hpp"
#include "laminate/verification_profile.hpp"

#include <cstdint>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::verification_profile;

namespace {

void transcript_replay(Transcript &transcript, Transcript &expected) {
    const std::vector<std::uint8_t> bytes{3, 1, 4, 1, 5};
    transcript.observe("bytes", bytes);
    expected.observe("bytes", bytes);
    transcript.observe("integer", 9);
    expected.observe("integer", 9);
    CHECK(transcript.challenge_fpk() == expected.challenge_fpk());
    CHECK(transcript.challenge_fq() == expected.challenge_fq());
    CHECK(transcript.challenge_fq2() == expected.challenge_fq2());
    CHECK(transcript.challenge_vector(3) == expected.challenge_vector(3));
    CHECK(transcript.challenge_fq2_vector(2) ==
          expected.challenge_fq2_vector(2));
    CHECK(transcript.challenge_bits(129) == expected.challenge_bits(129));
}

void exclusive_routing_and_replay() {
    VerificationBreakdown breakdown;
    Transcript actual("test/verification-profile");
    Transcript expected("test/verification-profile");
    {
        const ScopedVerificationSession session(breakdown);
        transcript_replay(actual, expected);
        const std::size_t recovered =
            breakdown.phase_entries(Category::Recovery);
        CHECK(recovered > 0);
        for (const Category category : {Category::PackingSNARK,
                                       Category::TerminalInputMLE,
                                       Category::WFNoise,
                                       Category::OutputDecryption}) {
            const ScopedVerificationPhase phase(category);
            transcript_replay(actual, expected);
            // A subprotocol's FS work is not reclassified as GKR recovery.
            CHECK(breakdown.phase_entries(Category::Recovery) == recovered);
        }
        {
            const ScopedVerificationPhase gate_pcs(
                Category::GkrPlaintext, false);
            transcript_replay(actual, expected);
            CHECK(breakdown.phase_entries(Category::Recovery) == recovered);
        }
        transcript_replay(actual, expected);
        CHECK(breakdown.phase_entries(Category::Recovery) > recovered);
    }
    CHECK(breakdown.phase_entries(Category::TerminalInputMLE) == 1);
    CHECK(breakdown.phase_entries(Category::PackingSNARK) == 1);
    CHECK(breakdown.phase_entries(Category::WFNoise) == 1);
    CHECK(breakdown.phase_entries(Category::OutputDecryption) == 1);
    CHECK(breakdown.total().wall_ms >= 0);
    CHECK(breakdown.total().cpu_ms >= 0);
    const auto before = breakdown.entries;
    transcript_replay(actual, expected);
    const ScopedVerificationPhase inactive(Category::Recovery);
    CHECK(breakdown.entries == before);
}

void additive_sessions_restore_after_exceptions() {
    VerificationBreakdown outer;
    VerificationBreakdown inner;
    {
        const ScopedVerificationSession session(outer);
        const ScopedVerificationPhase packing(Category::PackingSNARK);
        try {
            const ScopedVerificationSession nested(inner);
            const ScopedVerificationPhase terminal(Category::TerminalInputMLE);
            throw std::runtime_error("test unwind");
        } catch (const std::runtime_error &) {
        }
        // Nested sessions and their scopes must restore the outer packing
        // category; this transcript operation must not enter recovery.
        Transcript transcript("test/restored-session");
        (void)transcript.challenge_fpk();
        CHECK(outer.phase_entries(Category::Recovery) == 0);
        CHECK(outer.phase_entries(Category::TerminalInputMLE) == 0);
    }
    CHECK(inner.phase_entries(Category::TerminalInputMLE) == 1);
    CHECK(inner.phase_entries(Category::PackingSNARK) == 0);
    {
        const ScopedVerificationSession session(outer);
        const ScopedVerificationPhase recovery(Category::Recovery);
    }
    CHECK(outer.phase_entries(Category::GkrPlaintext) == 2);
    CHECK(outer.phase_entries(Category::Recovery) == 1);
    CHECK(outer.phase_entries(Category::PackingSNARK) == 1);
}

void totals_include_each_component_once() {
    VerificationBreakdown first;
    first.recovery = {1, 2};
    first.gkr_plaintext = {3, 4};
    first.terminal_input_mle = {5, 6};
    first.packing_snark = {7, 8};
    first.wf_noise = {9, 10};
    first.output_decryption = {11, 12};
    CHECK(first.gkr().wall_ms == 4);
    CHECK(first.gkr().cpu_ms == 6);
    CHECK(first.vcoed().wall_ms == 25);
    CHECK(first.vcoed().cpu_ms == 30);
    CHECK(first.total().wall_ms == 36);
    CHECK(first.total().cpu_ms == 42);
    VerificationBreakdown second = first;
    second += first;
    CHECK(second.vcoed().wall_ms == 50);
    CHECK(second.total().cpu_ms == 84);
}

void pauses_exclude_callbacks_and_restore_after_exceptions() {
    VerificationBreakdown outer;
    VerificationBreakdown callback;
    {
        const ScopedVerificationSession session(outer);
        const ScopedVerificationPhase packing(Category::PackingSNARK);
        try {
            const ScopedVerificationPause pause;
            const auto paused_entries = outer.entries;
            const Elapsed paused_total = outer.total();
            {
                // Nested inactive pauses are no-ops. Transcript hooks and
                // explicit scopes must not accidentally reactivate outer.
                const ScopedVerificationPause nested_pause;
                const ScopedVerificationPhase recovery(Category::Recovery);
                Transcript transcript("test/paused-transcript");
                (void)transcript.challenge_fpk();
                {
                    const ScopedVerificationSession nested(callback);
                    const ScopedVerificationPhase terminal(
                        Category::TerminalInputMLE);
                    (void)transcript.challenge_fpk();
                }
                (void)transcript.challenge_fpk();
            }
            CHECK(outer.entries == paused_entries);
            CHECK(outer.total().wall_ms == paused_total.wall_ms);
            CHECK(outer.total().cpu_ms == paused_total.cpu_ms);
            throw std::runtime_error("test paused callback unwind");
        } catch (const std::runtime_error &) {
        }
        // The exception restores both the active ledger and packing phase:
        // implicit transcript recovery stays suppressed, explicit WF records.
        Transcript resumed("test/resumed-transcript");
        (void)resumed.challenge_fpk();
        const ScopedVerificationPhase noise(Category::WFNoise);
    }
    CHECK(outer.phase_entries(Category::Recovery) == 0);
    CHECK(outer.phase_entries(Category::PackingSNARK) == 1);
    CHECK(outer.phase_entries(Category::WFNoise) == 1);
    CHECK(outer.phase_entries(Category::TerminalInputMLE) == 0);
    CHECK(callback.phase_entries(Category::GkrPlaintext) == 1);
    CHECK(callback.phase_entries(Category::TerminalInputMLE) == 1);
    CHECK(callback.phase_entries(Category::Recovery) == 0);
    const auto entries = outer.entries;
    {
        const ScopedVerificationPause inactive;
        Transcript transcript("test/inactive-pause");
        (void)transcript.challenge_fpk();
    }
    CHECK(outer.entries == entries);
}

} // namespace

int main() {
    test::Runner runner("test_verification_profile");
    runner.run("exclusive phase routing preserves transcript replay",
               exclusive_routing_and_replay);
    runner.run("additive nested sessions restore after exceptions",
               additive_sessions_restore_after_exceptions);
    runner.run("component totals have no overlap",
               totals_include_each_component_once);
    runner.run("pauses exclude callbacks and restore after exceptions",
               pauses_exclude_callbacks_and_restore_after_exceptions);
    return runner.summary();
}
