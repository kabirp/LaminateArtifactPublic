#ifndef LAMINATE_STORAGE_EXTERNAL_RECORD_SORT_HPP
#define LAMINATE_STORAGE_EXTERNAL_RECORD_SORT_HPP

/// @file external_record_sort.hpp
/// @brief Bounded-memory external ordering of opaque serialized records.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace laminate::storage {

/// Physical framing of the current temporary-run format. Admission helpers
/// use these constants so their byte formulas cannot drift from the sorter.
inline constexpr std::uint64_t kExternalRecordSortRunHeaderBytes = 16;
inline constexpr std::uint64_t kExternalRecordSortRecordFramingBytes = 24;

class ExternalRecordSortBudget {
  public:
    ExternalRecordSortBudget(std::uint64_t max_live_bytes,
                             std::uint64_t min_free_bytes);

    std::uint64_t current_live_bytes() const;
    std::uint64_t peak_live_bytes() const;
    /// Bytes concurrently owned by the final artifact writer. Updating this
    /// value makes the same ceiling cover final output plus temporary runs.
    void set_external_live_bytes(std::uint64_t bytes);
    std::uint64_t external_live_bytes() const;
    std::uint64_t peak_combined_live_bytes() const;

  private:
    void require(const std::filesystem::path &directory,
                 std::uint64_t additional) const;
    void acquire(std::uint64_t bytes);
    void release(std::uint64_t bytes);

    std::uint64_t max_live_bytes_ = 0;
    std::uint64_t min_free_bytes_ = 0;
    std::uint64_t current_live_bytes_ = 0;
    std::uint64_t peak_live_bytes_ = 0;
    std::uint64_t external_live_bytes_ = 0;
    std::uint64_t peak_combined_live_bytes_ = 0;

    friend class ExternalSerializedRecordSorter;
};

struct ExternalRecordSortOptions {
    /// Existing private directory in which one owned workspace is created.
    std::filesystem::path parent_directory;
    std::string workspace_name;
    std::uint64_t max_live_temporary_bytes = 0;
    std::uint64_t min_free_bytes = 0;
    /// Sorters that overlap in time share one exact live-byte cap.
    std::shared_ptr<ExternalRecordSortBudget> shared_budget;
    std::size_t max_buffered_records = 0;
    /// Exact sum of opaque payload lengths retained in the input buffer.
    /// A single record larger than this cap is rejected.
    std::uint64_t max_buffered_payload_bytes = 0;
    std::size_t merge_fan_in = 16;
};

struct ExternalRecordSortReport {
    std::uint64_t records = 0;
    std::uint64_t payload_bytes = 0;
    std::uint64_t temporary_bytes_written = 0;
    std::uint64_t temporary_bytes_deleted = 0;
    std::uint64_t peak_live_temporary_bytes = 0;
    std::uint64_t retained_temporary_bytes = 0;
    std::uint64_t initial_runs = 0;
    std::uint64_t runs_created = 0;
    std::uint64_t merge_passes = 0;
    std::size_t maximum_open_runs = 0;
    std::uint64_t peak_open_run_payload_bytes = 0;
    std::size_t peak_buffered_records = 0;
    std::uint64_t peak_buffered_payload_bytes = 0;
    /// Payload capacities plus `PendingRecord` objects. Allocator and shared
    /// ownership control-block overhead is implementation-dependent and is
    /// intentionally not claimed as exact.
    std::uint64_t peak_estimated_buffered_host_bytes = 0;

    bool operator==(const ExternalRecordSortReport &) const = default;
};

/// Sort opaque records by a public key. Equal keys retain append order.
///
/// Records are accumulated into caller-bounded sorted runs and merged with a
/// bounded fan-in. Temporary files live in one newly-created child directory.
/// Successful completion removes every owned file and that directory. Failure
/// cleanup removes only files whose type and length still match the ledger;
/// unfamiliar or replaced paths are left for diagnosis.
class ExternalSerializedRecordSorter {
  public:
    explicit ExternalSerializedRecordSorter(ExternalRecordSortOptions options);
    ~ExternalSerializedRecordSorter();

    ExternalSerializedRecordSorter(
        const ExternalSerializedRecordSorter &) = delete;
    ExternalSerializedRecordSorter &operator=(
        const ExternalSerializedRecordSorter &) = delete;

    void append(
        std::uint64_t destination,
        std::shared_ptr<const std::vector<std::uint8_t>> payload);

    /// Flush, merge, and visit records in nondecreasing key order. Equal keys
    /// retain their append order.
    /// This object accepts no more records after this call.
    ExternalRecordSortReport write_sorted(
        const std::function<void(
            std::uint64_t, std::span<const std::uint8_t>)> &visitor);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace laminate::storage

#endif
