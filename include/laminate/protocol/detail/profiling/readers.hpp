#ifndef LAMINATE_PROTOCOL_DETAIL_PROFILING_READERS_HPP
#define LAMINATE_PROTOCOL_DETAIL_PROFILING_READERS_HPP

/// @file readers.hpp
/// @brief Timed message readers for benchmark-only verification paths.

#include "laminate/gkr/base.hpp"
#include "laminate/protocol/detail/packing/transcript_reader.hpp"
#include "laminate/protocol/detail/profiling/clock.hpp"
#include "laminate/protocol/metrics/types.hpp"
#include "laminate/verification_profile.hpp"

namespace laminate::protocol::profiling_detail {

template <fhe::FheBackend Backend> class BaseMessageReader {
  public:
    BaseMessageReader(const typename Backend::ClientContext &client,
                      BaseVerifierTimings &timings)
        : client_(client), timings_(timings) {}

    std::vector<Fpk> read(
        const fhe::ExtensionValue<Backend> &value) const {
        const verification_profile::ScopedVerificationPhase recovery(
            verification_profile::Category::Recovery);
        const Stopwatch timer;
        std::vector<Fpk> values =
            fhe::read_extension_value<Backend>(client_, value);
        const Elapsed elapsed = timer.stop();
        timings_.packed_message_verification_wall_ms += elapsed.wall_ms;
        timings_.packed_message_verification_cpu_ms += elapsed.cpu_ms;
        return values;
    }

  private:
    const typename Backend::ClientContext &client_;
    BaseVerifierTimings &timings_;
};

/// Keep fixed-message decoding in recovery after packed digit reconstruction.
class PackedTranscriptReader : public detail::PackedTranscriptReader {
  public:
    using detail::PackedTranscriptReader::PackedTranscriptReader;

    std::vector<Fpk> read(const gkr::CommittedPackedMessage &committed,
                         std::size_t value_count) {
        const verification_profile::ScopedVerificationPhase recovery(
            verification_profile::Category::Recovery);
        return detail::PackedTranscriptReader::read(committed, value_count);
    }
};

} // namespace laminate::protocol::profiling_detail

#endif // LAMINATE_PROTOCOL_DETAIL_PROFILING_READERS_HPP
