#ifndef LAMINATE_PAYLOAD_CHECKPOINT_READERS_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_READERS_HPP

/// @file readers.hpp
/// @brief Streaming readers for natural and proof-ingress layer artifacts.

#include "laminate/payload/checkpoint/certification.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::payload {

template <fhe::PersistableFheBackend Backend>
class PayloadCheckpointReplayTrace;

template <fhe::PersistableFheBackend Backend>
class PayloadCheckpointReplayLayerReader {
  public:
    std::optional<fhe::FheValue<Backend>> next() {
        if (position_ == end_) {
            return std::nullopt;
        }

        const std::optional<std::size_t> stored =
            storage_.stored_ordinal_of(position_);
        if (stored) {
            reader_.seek_to(*stored);
            ++position_;
            return next_stored(reader_);
        }

        ++position_;
        return fhe::FheValue<Backend>::public_zero();
    }

    void rewind() {
        reader_.rewind();
        position_ = begin_;
    }
    std::size_t begin() const { return begin_; }
    std::size_t end() const { return end_; }
    std::size_t position() const { return position_; }
    std::uint64_t encoded_bytes_read() const {
        return encoded_bytes_read_;
    }
    std::uint64_t serialized_records_read() const {
        return serialized_records_read_;
    }
    std::size_t resident_ciphertexts_held() const { return 0; }

  private:
    fhe::FheValue<Backend> next_stored(
        trace_storage::ValidatedPrivateLayerRangeReader &reader) {
        const std::optional<std::span<const std::uint8_t>> encoded =
            reader.next_view();
        if (!encoded) {
            throw std::runtime_error(
                "PayloadCheckpointReplayLayerReader: missing stored record");
        }
        checkpoint_replay_execution_detail::accumulate(
            encoded_bytes_read_,
            checkpoint_replay_execution_detail::checked_count(
                encoded->size(), "checkpoint reader encoded bytes"),
            "checkpoint reader encoded bytes");
        checkpoint_replay_execution_detail::accumulate(
            serialized_records_read_, 1,
            "checkpoint reader serialized records");
        checkpoint_replay_execution_detail::accumulate(
            *aggregate_encoded_bytes_read_,
            checkpoint_replay_execution_detail::checked_count(
                encoded->size(), "checkpoint aggregate read bytes"),
            "checkpoint aggregate read bytes");
        checkpoint_replay_execution_detail::accumulate(
            *aggregate_framed_record_bytes_read_,
            checkpoint_replay_execution_detail::checked_add(
                checkpoint_replay_execution_detail::checked_count(
                    encoded->size(), "checkpoint framed record bytes"),
                sizeof(std::uint64_t),
                "checkpoint framed record bytes"),
            "checkpoint aggregate framed record bytes");
        return fhe::decode_validated_private_fhe_value_record<Backend>(
                *eval_, *encoded);
    }

    PayloadCheckpointReplayLayerReader(
        const typename Backend::EvalContext &eval,
        LayerStorageLayout storage, std::size_t begin, std::size_t end,
        trace_storage::ValidatedPrivateLayerRangeReader reader,
        std::uint64_t &aggregate_encoded_bytes_read,
        std::uint64_t &aggregate_framed_record_bytes_read)
        : eval_(&eval), storage_(std::move(storage)),
          reader_(std::move(reader)),
          aggregate_encoded_bytes_read_(&aggregate_encoded_bytes_read),
          aggregate_framed_record_bytes_read_(
              &aggregate_framed_record_bytes_read),
          begin_(begin), end_(end), position_(begin) {}

    const typename Backend::EvalContext *eval_;
    LayerStorageLayout storage_;
    trace_storage::ValidatedPrivateLayerRangeReader reader_;
    std::uint64_t *aggregate_encoded_bytes_read_;
    std::uint64_t *aggregate_framed_record_bytes_read_;
    std::uint64_t encoded_bytes_read_ = 0;
    std::uint64_t serialized_records_read_ = 0;
    std::size_t begin_ = 0;
    std::size_t end_ = 0;
    std::size_t position_ = 0;

    template <fhe::PersistableFheBackend>
    friend class PayloadCheckpointReplayTrace;
};

/// Reader over the serialized distinct records of one active proof-ingress
/// layer. Ordinals are storage ordinals; each returned record carries its
/// representative padded protocol index. Padding and aliases have no extra
/// record, and ciphertexts were already normalized once at publication.
template <fhe::PersistableFheBackend Backend>
class PayloadCheckpointReplayActiveLayerReader {
  public:
    std::optional<FileEncryptedTraceActiveWire<Backend>> next() {
        const std::size_t stored = reader_.position();
        const std::optional<std::span<const std::uint8_t>> encoded =
            reader_.next_view();
        if (!encoded) {
            return std::nullopt;
        }
        checkpoint_replay_execution_detail::accumulate(
            encoded_bytes_read_,
            checkpoint_replay_execution_detail::checked_count(
                encoded->size(), "checkpoint active-reader encoded bytes"),
            "checkpoint active-reader encoded bytes");
        checkpoint_replay_execution_detail::accumulate(
            serialized_records_read_, 1,
            "checkpoint active-reader serialized records");
        checkpoint_replay_execution_detail::accumulate(
            *aggregate_encoded_bytes_read_,
            checkpoint_replay_execution_detail::checked_count(
                encoded->size(), "checkpoint aggregate active-read bytes"),
            "checkpoint aggregate active-read bytes");
        checkpoint_replay_execution_detail::accumulate(
            *aggregate_framed_record_bytes_read_,
            checkpoint_replay_execution_detail::checked_add(
                checkpoint_replay_execution_detail::checked_count(
                    encoded->size(),
                    "checkpoint framed active-record bytes"),
                sizeof(std::uint64_t),
                "checkpoint framed active-record bytes"),
            "checkpoint aggregate framed active-record bytes");
        return FileEncryptedTraceActiveWire<Backend>{
            storage_.representative_padded_index_of(stored),
            fhe::decode_validated_private_fhe_value_record<Backend>(
                    *eval_, *encoded)};
    }

    void rewind() { reader_.rewind(); }
    /// Reposition by storage ordinal while retaining the active replay
    /// artifact's single reader handle.
    void seek_to(std::size_t stored_position) {
        reader_.seek_to(stored_position);
    }
    std::size_t begin() const { return reader_.begin(); }
    std::size_t end() const { return reader_.end(); }
    std::size_t position() const { return reader_.position(); }
    std::uint64_t encoded_bytes_read() const {
        return encoded_bytes_read_;
    }
    std::uint64_t serialized_records_read() const {
        return serialized_records_read_;
    }
    std::size_t resident_ciphertexts_held() const { return 0; }

  private:
    PayloadCheckpointReplayActiveLayerReader(
        const typename Backend::EvalContext &eval,
        LayerStorageLayout storage,
        trace_storage::ValidatedPrivateLayerRangeReader reader,
        std::uint64_t &aggregate_encoded_bytes_read,
        std::uint64_t &aggregate_framed_record_bytes_read)
        : eval_(&eval), storage_(std::move(storage)),
          reader_(std::move(reader)),
          aggregate_encoded_bytes_read_(&aggregate_encoded_bytes_read),
          aggregate_framed_record_bytes_read_(
              &aggregate_framed_record_bytes_read) {}

    const typename Backend::EvalContext *eval_;
    LayerStorageLayout storage_;
    trace_storage::ValidatedPrivateLayerRangeReader reader_;
    std::uint64_t *aggregate_encoded_bytes_read_;
    std::uint64_t *aggregate_framed_record_bytes_read_;
    std::uint64_t encoded_bytes_read_ = 0;
    std::uint64_t serialized_records_read_ = 0;

    template <fhe::PersistableFheBackend>
    friend class PayloadCheckpointReplayTrace;
};

/// Sequential reader over one eagerly packed Laned S' layer. Positions are
/// packed-ciphertext indices, not original wire indices.
template <fhe::PersistableFheBackend Backend>
class PayloadCheckpointReplayPackedLayerReader {
  public:
    std::optional<fhe::FheValue<Backend>> next() {
        const std::optional<std::span<const std::uint8_t>> encoded =
            reader_.next_view();
        if (!encoded) {
            return std::nullopt;
        }
        checkpoint_replay_execution_detail::accumulate(
            encoded_bytes_read_,
            checkpoint_replay_execution_detail::checked_count(
                encoded->size(), "packed witness reader encoded bytes"),
            "packed witness reader encoded bytes");
        checkpoint_replay_execution_detail::accumulate(
            *aggregate_encoded_bytes_read_,
            checkpoint_replay_execution_detail::checked_count(
                encoded->size(), "packed witness aggregate read bytes"),
            "packed witness aggregate read bytes");
        checkpoint_replay_execution_detail::accumulate(
            *aggregate_framed_record_bytes_read_,
            checkpoint_replay_execution_detail::checked_add(
                checkpoint_replay_execution_detail::checked_count(
                    encoded->size(), "packed witness framed bytes"),
                sizeof(std::uint64_t), "packed witness framed bytes"),
            "packed witness aggregate framed bytes");
        return fhe::decode_validated_private_fhe_value_record<Backend>(
            *eval_, *encoded);
    }

    void rewind() { reader_.rewind(); }
    std::size_t position() const { return reader_.position(); }
    std::size_t size() const { return reader_.end() - reader_.begin(); }
    std::uint64_t encoded_bytes_read() const { return encoded_bytes_read_; }

  private:
    PayloadCheckpointReplayPackedLayerReader(
        const typename Backend::EvalContext &eval,
        trace_storage::ValidatedPrivateLayerRangeReader reader,
        std::uint64_t &aggregate_encoded_bytes_read,
        std::uint64_t &aggregate_framed_record_bytes_read)
        : eval_(&eval), reader_(std::move(reader)),
          aggregate_encoded_bytes_read_(&aggregate_encoded_bytes_read),
          aggregate_framed_record_bytes_read_(
              &aggregate_framed_record_bytes_read) {}

    const typename Backend::EvalContext *eval_;
    trace_storage::ValidatedPrivateLayerRangeReader reader_;
    std::uint64_t *aggregate_encoded_bytes_read_;
    std::uint64_t *aggregate_framed_record_bytes_read_;
    std::uint64_t encoded_bytes_read_ = 0;

    template <fhe::PersistableFheBackend>
    friend class PayloadCheckpointReplayTrace;
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_CHECKPOINT_READERS_HPP
