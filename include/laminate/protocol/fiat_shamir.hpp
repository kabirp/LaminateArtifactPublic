#ifndef LAMINATE_PROTOCOL_FIAT_SHAMIR_HPP
#define LAMINATE_PROTOCOL_FIAT_SHAMIR_HPP

#include "laminate/transcript/transcript.hpp"

#include <cstdint>
#include <string_view>

namespace laminate::protocol {

/// Packed variants compile one ordered interaction: committed GKR and its
/// gate openings, followed by the packing argument and its PCS openings.
inline constexpr std::string_view kPackedFiatShamirSchedule =
    "single-transcript-gkr-then-packing-v1";

/// Bind the composition order before the first GKR challenge, independently
/// of any caller-selected statement or benchmark domain.
inline void observe_packed_fiat_shamir_schedule(Transcript &transcript) {
    transcript.observe(kPackedFiatShamirSchedule, std::uint64_t{1});
}

} // namespace laminate::protocol

#endif
