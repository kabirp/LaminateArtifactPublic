#ifndef LAMINATE_GKR_DETAIL_BASE_VERIFICATION_DIAGNOSTIC_HPP
#define LAMINATE_GKR_DETAIL_BASE_VERIFICATION_DIAGNOSTIC_HPP

/// @file diagnostic.hpp
/// @brief Failure location for a Base client verification.
///
/// Records the verifier's last stage, layer, and sumcheck round for rejection
/// diagnostics. Verification arithmetic does not read this state; it cannot
/// affect acceptance.

#include <cstddef>
#include <exception>
#include <limits>
#include <string>
#include <utility>

namespace laminate::gkr::base_detail {

/// Where the current Base verification stands. The verifier overwrites this as
/// it advances; because verification returns at the first failing check, the
/// last recorded position is the failure location whenever `run()` rejects.
struct BaseVerifierDiagnostic {
    static constexpr std::size_t kNoIndex =
        std::numeric_limits<std::size_t>::max();

    std::string stage;            ///< e.g. "multiplication-reduction".
    std::size_t layer = kNoIndex; ///< Circuit layer under reduction, if any.
    std::size_t round = kNoIndex; ///< Sumcheck round within the reduction.
    std::string detail;           ///< Specific reason or exception message.

    void reset() {
        stage.clear();
        layer = kNoIndex;
        round = kNoIndex;
        detail.clear();
    }

    /// Enter a named stage, optionally attached to a circuit layer. Clears the
    /// finer round and detail fields so a later failure reports them freshly.
    void enter(std::string step, std::size_t reduction_layer = kNoIndex) {
        stage = std::move(step);
        layer = reduction_layer;
        round = kNoIndex;
        detail.clear();
    }

    std::string to_string() const {
        std::string result = stage.empty() ? "unspecified" : stage;
        if (layer != kNoIndex) {
            result += " | layer " + std::to_string(layer);
        }
        if (round != kNoIndex) {
            result += " | ciphertext-index round " + std::to_string(round);
        }
        if (!detail.empty()) {
            result += " | " + detail;
        }
        return result;
    }
};

/// The current thread's Base verification diagnostic. A single verification
/// runs on one thread, so a thread-local keeps this out of every protocol
/// signature while remaining correct if verifications ever run concurrently.
inline BaseVerifierDiagnostic &base_verifier_diagnostic() {
    thread_local BaseVerifierDiagnostic diagnostic;
    return diagnostic;
}

/// Record a caught verifier exception's message and return the rejection value
/// the Base verifier uses for a swallowed exception.
inline bool record_base_verifier_exception(const std::exception &error) {
    BaseVerifierDiagnostic &diagnostic = base_verifier_diagnostic();
    if (diagnostic.stage.empty()) {
        diagnostic.stage = "exception";
    }
    diagnostic.detail = std::string("exception: ") + error.what();
    return false;
}

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_VERIFICATION_DIAGNOSTIC_HPP
