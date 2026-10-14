#ifndef LAMINATE_BENCH_CLIENT_COMPUTATION_HPP
#define LAMINATE_BENCH_CLIENT_COMPUTATION_HPP

#include "benchmark_support.hpp"
#include "laminate/verification_profile.hpp"

#include <string>
#include <string_view>

namespace laminate::bench {

inline constexpr std::string_view kClientComputationScope =
    "input-encryption-output-decryption-vcoed-verification;"
    "excludes-preprocessing-load-transport-peer-wait-and-output-noise-audit";

/// Emit the disjoint, measured client computation hierarchy shared by Base,
/// Folded and Laned. The enclosing wall timers remain separate diagnostics.
inline Timing emit_client_computation(
    const Record &record, const Timing &encryption,
    const verification_profile::VerificationBreakdown &verification) {
    const auto pair = [&](std::string_view prefix, const auto &value) {
        record.real(std::string(prefix) + ".wall_ms", value.wall_ms);
        record.real(std::string(prefix) + ".cpu_ms", value.cpu_ms);
    };
    const auto gkr = verification.gkr();
    const auto vcoed = verification.vcoed();
    const Timing total{
        encryption.wall_ms + verification.output_decryption.wall_ms + vcoed.wall_ms,
        encryption.cpu_ms + verification.output_decryption.cpu_ms + vcoed.cpu_ms};
    record.text("timing.client.computation.schema", "vcoed-client-computation-v1");
    pair("timing.client.decrypt_output", verification.output_decryption);
    pair("timing.client.verify.gkr.transcript_recovery", verification.recovery);
    pair("timing.client.verify.gkr.plaintext", verification.gkr_plaintext);
    pair("timing.client.verify.gkr", gkr);
    pair("timing.client.verify.terminal_input_mle", verification.terminal_input_mle);
    // In packed variants, this field measures the Spartan packing suffix
    // of the composed argument, including its matrix and PCS checks.
    pair("timing.client.verify.transcript_packing_snark", verification.packing_snark);
    pair("timing.client.verify.well_formedness_noise", verification.wf_noise);
    pair("timing.client.verify.vcoed", vcoed);
    pair("timing.client.computation_total", total);
    record.text("timing.client.computation_total.scope",
                std::string(kClientComputationScope));
    return total;
}

} // namespace laminate::bench

#endif
