/// @file ipcs.cpp
/// @brief Canonical PCS commitment encoding.

#include "laminate/spartan/ipcs.hpp"

namespace laminate::spartan {
namespace {

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

} // namespace

std::vector<std::uint8_t>
encode_pcs_commitment(const PcsCommitment &commitment) {
    std::vector<std::uint8_t> output;
    output.reserve(8 + commitment.root.size() + 8 + 8 + 8 + 8);
    append_u64(output, commitment.scheme);
    output.insert(output.end(), commitment.root.begin(),
                  commitment.root.end());
    append_u64(output, commitment.evaluation_count);
    append_u64(output, commitment.width);
    append_u64(output, commitment.log_rate);
    append_u64(output, commitment.query_count);
    return output;
}

} // namespace laminate::spartan
