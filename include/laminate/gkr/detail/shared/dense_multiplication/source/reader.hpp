#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_READER_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_READER_HPP

/// @file reader.hpp
/// @brief Sequential pair access over a validated multiplication artifact.

#include "laminate/gkr/detail/shared/dense_multiplication/source/resource_bounds.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace laminate::gkr::detail {

/// One immutable operand returned by the file reader.
///
/// A one-use operand owns its decoded value directly. A repeated operand
/// shares its current bounded-cache entry. Eviction never invalidates an
/// operand still owned by a returned pair. The
/// move-only boundary prevents an accidental ciphertext copy in either case.
template <fhe::PersistableFheBackend Backend>
class FileDenseMultiplicationOperand {
  public:
    using Value = fhe::FheValue<Backend>;

    static FileDenseMultiplicationOperand own(Value value) {
        return FileDenseMultiplicationOperand(std::move(value));
    }

    static FileDenseMultiplicationOperand
    share(std::shared_ptr<const Value> value) {
        return FileDenseMultiplicationOperand(std::move(value));
    }

    FileDenseMultiplicationOperand(
        const FileDenseMultiplicationOperand &) = delete;
    FileDenseMultiplicationOperand &operator=(
        const FileDenseMultiplicationOperand &) = delete;
    FileDenseMultiplicationOperand(
        FileDenseMultiplicationOperand &&) = default;
    FileDenseMultiplicationOperand &operator=(
        FileDenseMultiplicationOperand &&) = default;

    const Value &value() const {
        if (const auto *owned = std::get_if<Value>(&value_)) {
            return *owned;
        }
        return *std::get<std::shared_ptr<const Value>>(value_);
    }

  private:
    explicit FileDenseMultiplicationOperand(Value value)
        : value_(std::move(value)) {}
    explicit FileDenseMultiplicationOperand(
        std::shared_ptr<const Value> value)
        : value_(std::move(value)) {}

    std::variant<Value, std::shared_ptr<const Value>> value_;
};

template <fhe::PersistableFheBackend Backend>
class FileDenseMultiplicationPair {
  public:
    using Value = fhe::FheValue<Backend>;
    using Operand = FileDenseMultiplicationOperand<Backend>;

    /// Canonical (non-bit-reversed) packed index.
    std::size_t packed_index = 0;

    /// Immutable operands for this logical pair. Aliased operands share the
    /// one value decoded and cached by the current source scan.
    const Value &left() const { return left_.value(); }
    const Value &right() const { return right_.value(); }

  private:
    FileDenseMultiplicationPair(
        std::size_t packed, Operand left, Operand right)
        : packed_index(packed), left_(std::move(left)),
          right_(std::move(right)) {}

    Operand left_;
    Operand right_;

    template <fhe::PersistableFheBackend>
    friend class FileDenseMultiplicationSourceReader;
};

/// Sequential logical-pair reader over the distinct-operand artifact.
///
/// Each call maps the next preprocessed physical position back to its
/// canonical packed index, decodes new operands in storage order, and serves
/// later aliases from a bounded repeated-operand cache. Evicted operands are
/// reread through a separate random-access handle, preserving buffered
/// sequential reads and prefetch for every operand's first use.
template <fhe::PersistableFheBackend Backend>
class FileDenseMultiplicationSourceReader {
  public:
    using Pair = FileDenseMultiplicationPair<Backend>;

    std::optional<Pair> next() {
        if (position_ == live_pair_count_) {
            return std::nullopt;
        }
        const std::size_t packed = aliases_.physical_pair_order[position_];
        auto left = read_operand(aliases_.left_operand[packed]);
        auto right = read_operand(aliases_.right_operand[packed]);
        ++position_;
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics_.pairs_read, 1,
            "packed multiplication reader pair count");
        statistics_.peak_live_decoded_values = std::max(
            statistics_.peak_live_decoded_values, cached_values_ + 2U);
        return Pair(packed, std::move(left), std::move(right));
    }

    void rewind() {
        reader_.rewind();
        // The alias handle remains random-access across passes. Rewinding it
        // would enable sequential prefetch for an arbitrary alias position.
        position_ = 0;
        cached_values_ = 0;
        cache_order_.clear();
        std::fill(seen_.begin(), seen_.end(), false);
        for (auto &value : cache_) {
            value.reset();
        }
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics_.rewinds, 1,
            "packed multiplication reader rewind count");
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics_.passes_started, 1,
            "packed multiplication reader pass count");
    }

    /// Number of logical live pairs visited by every scan.
    std::size_t size() const { return live_pair_count_; }
    /// Padded algebraic pair domain; omitted positions are public zero.
    std::size_t domain_size() const { return pair_count_; }
    std::size_t position() const { return position_; }
    std::uint64_t stored_value_count() const {
        return file_dense_multiplication_source_detail::checked_count(
            aliases_.operands.size(),
            "packed multiplication stored value count");
    }

    const FileDenseMultiplicationSourceReadStatistics &statistics() const {
        return statistics_;
    }

    payload::FileTraceStoreReadDiagnostics sequential_read_diagnostics() const {
        return reader_.diagnostics();
    }

    payload::FileTraceStoreReadDiagnostics alias_read_diagnostics() const {
        return alias_reader_ ? alias_reader_->diagnostics()
                             : payload::FileTraceStoreReadDiagnostics{};
    }

  private:
    FileDenseMultiplicationSourceReader(
        const typename Backend::EvalContext &eval,
        payload::trace_storage::ValidatedPrivateLayerRangeReader
            reader,
        std::optional<payload::trace_storage::ValidatedPrivateLayerRangeReader>
            alias_reader,
        const FileDenseMultiplicationSourceDescriptor &descriptor,
        DenseMultiplicationAliasPlan aliases)
        : eval_(&eval), reader_(std::move(reader)),
          alias_reader_(std::move(alias_reader)),
          pair_count_(descriptor.pair_count),
          live_pair_count_(descriptor.live_pair_count),
          required_rns_limbs_(
              descriptor.packed_proof_ingress_rns_limbs),
          aliases_(std::move(aliases)),
          seen_(aliases_.operands.size(), false),
          cache_(aliases_.operands.size()) {
        if (aliases_.pair_count != pair_count_ ||
            aliases_.live_pair_count != live_pair_count_ ||
            aliases_.operands.size() != descriptor.stored_value_count) {
            throw std::invalid_argument(
                "packed multiplication reader alias plan mismatch");
        }
    }

    typename Pair::Operand read_operand(std::size_t operand) {
        if (operand >= aliases_.operands.size()) {
            throw std::runtime_error(
                "packed multiplication operand id is out of range");
        }
        if (cache_[operand]) {
            return Pair::Operand::share(cache_[operand]);
        }
        const std::size_t expected =
            aliases_.storage_ordinal_by_operand[operand];
        auto *selected_reader = &reader_;
        if (seen_[operand]) {
            if (!alias_reader_ || expected >= reader_.position()) {
                throw std::runtime_error(
                    "packed multiplication alias precedes its first use");
            }
            alias_reader_->seek_to(expected);
            selected_reader = &*alias_reader_;
        } else if (reader_.position() != expected) {
            throw std::runtime_error(
                "packed multiplication operand storage order drifted");
        }
        const std::optional<std::span<const std::uint8_t>> encoded =
            selected_reader->next_view();
        if (!encoded) {
            throw std::runtime_error(
                "packed multiplication source ended before a live side");
        }
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics_.values_read, 1,
            "packed multiplication reader value count");
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics_.logical_record_bytes_read,
            static_cast<std::uint64_t>(encoded->size()),
            "packed multiplication reader bytes");
        auto decoded = fhe::decode_validated_private_fhe_value_record<Backend>(
            *eval_, *encoded);
        if (decoded.is_encrypted()) {
            validate_dense_artifact_ingress_ciphertext<Backend>(
                *eval_, decoded.ciphertext(), required_rns_limbs_,
                "dense multiplication source");
        }
        if (!seen_[operand]) {
            file_dense_multiplication_source_detail::checked_accumulate(
                statistics_.distinct_values_read, 1,
                "packed multiplication reader distinct value count");
            seen_[operand] = true;
        }
        if (aliases_.operand_occurrences[operand] > 1U) {
            if (cached_values_ == kDenseMultiplicationReaderCacheValues) {
                cache_[cache_order_.front()].reset();
                cache_order_.pop_front();
                --cached_values_;
            }
            cache_order_.push_back(operand);
            cache_[operand] =
                std::make_shared<const fhe::FheValue<Backend>>(
                    std::move(decoded));
            ++cached_values_;
            return Pair::Operand::share(cache_[operand]);
        }
        return Pair::Operand::own(std::move(decoded));
    }

    const typename Backend::EvalContext *eval_;
    payload::trace_storage::ValidatedPrivateLayerRangeReader
        reader_;
    std::optional<payload::trace_storage::ValidatedPrivateLayerRangeReader>
        alias_reader_;
    std::size_t pair_count_;
    std::size_t live_pair_count_;
    std::size_t required_rns_limbs_;
    DenseMultiplicationAliasPlan aliases_;
    // Coverage survives decoded-value eviction; one bit per stored operand.
    std::vector<bool> seen_;
    std::deque<std::size_t> cache_order_;
    std::vector<std::shared_ptr<const fhe::FheValue<Backend>>> cache_;
    std::size_t cached_values_ = 0;
    std::size_t position_ = 0;
    FileDenseMultiplicationSourceReadStatistics statistics_;

    template <fhe::PersistableFheBackend>
    friend class FileDenseMultiplicationSource;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_READER_HPP
