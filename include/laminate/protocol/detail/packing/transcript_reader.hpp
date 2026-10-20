#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_TRANSCRIPT_READER_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_TRANSCRIPT_READER_HPP

/// @file transcript_reader.hpp
/// @brief Read logical GKR values recovered from transcript packing.

#include "laminate/fhe/layout/fixed_message.hpp"
#include "laminate/field/fpk.hpp"
#include "laminate/gkr/ciphertext_commitment.hpp"

#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::protocol::detail {

/// Decode one fixed 16-cell plaintext message into one or two F_{p^8} values.
inline std::vector<Fpk> decode_fixed_message(
    std::span<const Fp> slots, std::size_t value_count) {
    if (value_count == 0 || value_count > 2 ||
        slots.size() < fhe::kFixedMessageCellCount) {
        throw std::invalid_argument(
            "decode_fixed_message: invalid slots or value count");
    }
    std::vector<Fpk> result;
    result.reserve(value_count);
    for (std::size_t value = 0; value < value_count; ++value) {
        Fpk::Coefficients coefficients{};
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            coefficients[coefficient] = slots[fhe::fixed_message_cell_slot(
                slots.size(), value * kExtensionDegree + coefficient)];
        }
        result.emplace_back(coefficients);
    }
    return result;
}

/// Sequential view of the `r` rounds recovered from packed digits. The
/// plaintext checker uses challenges recorded by the earlier public replay;
/// reading a recovered message does not advance the transcript.
///
/// The commitment argument makes the verifier call site read like the proof:
/// it consumes a committed message. Commitment equality itself is checked in
/// one batch before any packed ciphertext is decrypted.
class PackedTranscriptReader {
  public:
    explicit PackedTranscriptReader(
        std::span<const fhe::SlotVector> logical_messages)
        : logical_messages_(logical_messages) {}

    std::vector<Fpk> read(const gkr::CommittedPackedMessage &committed,
                          std::size_t value_count) {
        if (cursor_ >= logical_messages_.size()) {
            throw std::out_of_range(
                "PackedTranscriptReader: proof consumes too many messages");
        }
        const fhe::SlotVector &logical = logical_messages_[cursor_];
        std::vector<Fpk> decoded =
            decode_fixed_message(logical, value_count);
        if (committed.is_public()) {
            const fhe::PublicPlaintext &plaintext = committed.plaintext();
            fhe::SlotVector scalar_slots;
            std::span<const Fp> public_slots;
            if (plaintext.is_scalar()) {
                scalar_slots = plaintext.materialize(logical.size());
                public_slots = scalar_slots;
            } else {
                public_slots = plaintext.slots();
            }
            if (decode_fixed_message(public_slots, value_count) != decoded) {
                throw std::invalid_argument(
                    "PackedTranscriptReader: recovered message differs "
                    "from its public GKR value");
            }
        }
        ++cursor_;
        return decoded;
    }

    bool all_messages_consumed() const {
        return cursor_ == logical_messages_.size();
    }

    std::size_t consumed_messages() const { return cursor_; }

  private:
    std::span<const fhe::SlotVector> logical_messages_;
    std::size_t cursor_ = 0;
};

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_TRANSCRIPT_READER_HPP
