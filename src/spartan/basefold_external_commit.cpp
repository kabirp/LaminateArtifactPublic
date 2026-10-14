/// @file basefold_external_commit.cpp
/// @brief Bounded-memory commitment construction for Spartan BaseFold.

#include "laminate/spartan/basefold_pcs.hpp"

#include "laminate/basefold/merkle.hpp"
#include "laminate/field/fq_ntt.hpp"
#include "laminate/field/fq_transform_kernels.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/params.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <chrono>
#include <exception>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace laminate::spartan {
namespace {

using basefold::Digest;
using basefold::MerkleTree;

constexpr std::string_view kSelectionIdentityDomain =
    "LaminateImpl/SpartanBaseFoldExternalCommitSelection/v1";
constexpr std::string_view kPassIdentityDomain =
    "LaminateImpl/SpartanBaseFoldExternalCommitPass/v1";
constexpr std::string_view kTreeIdentityDomain =
    "LaminateImpl/SpartanBaseFoldExternalCommitTree/v1";
constexpr std::string_view kPassValuesArray = "values";
constexpr std::string_view kBaseTreePostorderArray =
    "base-tree-postorder";
constexpr std::string_view kScratchTreePostorderArray =
    "tree-postorder";
constexpr std::size_t kMerkleLeafMaxElements = 64;
constexpr std::size_t kDigestBufferElements = 1024;
constexpr std::size_t kMaximumAutomaticCacheRadixElements =
    std::size_t{1} << 17U;

std::uint64_t checked_u64(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) + " exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::size_t checked_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

std::size_t log2_exact(std::size_t value) {
    if (!std::has_single_bit(value)) {
        throw std::invalid_argument(
            "BaseFold external commitment size is not a power of two");
    }
    return static_cast<std::size_t>(std::bit_width(value) - 1U);
}

std::size_t checked_codeword_size(std::size_t message_size,
                                  std::size_t log_rate) {
    const std::size_t message_log = log2_exact(message_size);
    if (log_rate > kOuterFieldTwoAdicity ||
        message_log > kOuterFieldTwoAdicity - log_rate ||
        message_log + log_rate >=
            std::numeric_limits<std::size_t>::digits) {
        throw std::invalid_argument(
            "BaseFold external commitment exceeds Fq two-adicity");
    }
    return std::size_t{1} << (message_log + log_rate);
}

std::size_t merkle_leaf_size(std::size_t codeword_size) {
    (void)log2_exact(codeword_size);
    return std::min(codeword_size, kMerkleLeafMaxElements);
}

std::size_t merkle_leaf_count(std::size_t codeword_size) {
    return codeword_size / merkle_leaf_size(codeword_size);
}

std::size_t merkle_node_count(std::size_t leaf_count) {
    if (!std::has_single_bit(leaf_count) ||
        leaf_count > std::numeric_limits<std::size_t>::max() / 2U + 1U) {
        throw std::overflow_error("BaseFold external tree size overflows");
    }
    return 2U * leaf_count - 1U;
}

std::string message_array_name(std::size_t column) {
    return "message-column-" + std::to_string(column);
}

std::string codeword_array_name(std::size_t column) {
    return "codeword-column-" + std::to_string(column);
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_string(std::vector<std::uint8_t> &output,
                   std::string_view value) {
    append_u64(output, checked_u64(value.size(), "identity string"));
    output.insert(output.end(), value.begin(), value.end());
}

void append_digest(std::vector<std::uint8_t> &output,
                   const laminate::Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

laminate::Digest selection_identity(
    const storage::NativeFieldArtifact &source,
    std::span<const BaseFoldArtifactColumn> columns,
    const BaseFoldPcsParameters &parameters) {
    std::vector<std::uint8_t> encoding(kSelectionIdentityDomain.begin(),
                                       kSelectionIdentityDomain.end());
    append_digest(encoding, source.identity());
    append_u64(encoding, checked_u64(parameters.log_rate, "log rate"));
    append_u64(encoding, checked_u64(parameters.query_count, "query count"));
    append_u64(encoding, checked_u64(columns.size(), "column count"));
    for (const BaseFoldArtifactColumn &column : columns) {
        const storage::NativeFieldArrayDescriptor &array =
            source.array(column.array_name);
        append_string(encoding, column.array_name);
        append_u64(encoding, static_cast<std::uint64_t>(array.kind));
        append_u64(encoding, array.element_count);
        append_digest(encoding, array.file_digest);
        append_u64(encoding, column.logical_evaluation_count);
        append_u64(encoding,
                   checked_u64(column.segments.size(), "segment count"));
        for (const BaseFoldArtifactColumnSegment &segment :
             column.segments) {
            append_u64(encoding, segment.logical_begin);
            append_u64(encoding, segment.stored_begin);
            append_u64(encoding, segment.element_count);
        }
    }
    return sha256(encoding);
}

laminate::Digest pass_identity(const laminate::Digest &selection,
                               std::size_t column, std::size_t pass,
                               std::string_view phase) {
    std::vector<std::uint8_t> encoding(kPassIdentityDomain.begin(),
                                       kPassIdentityDomain.end());
    append_digest(encoding, selection);
    append_u64(encoding, checked_u64(column, "column index"));
    append_u64(encoding, checked_u64(pass, "pass index"));
    append_string(encoding, phase);
    return sha256(encoding);
}

laminate::Digest tree_identity(const laminate::Digest &selection) {
    std::vector<std::uint8_t> encoding(kTreeIdentityDomain.begin(),
                                       kTreeIdentityDomain.end());
    append_digest(encoding, selection);
    return sha256(encoding);
}

std::filesystem::path normalized(const std::filesystem::path &path) {
    if (path.empty()) {
        throw std::invalid_argument("BaseFold external path is empty");
    }
    return std::filesystem::canonical(path);
}

bool path_prefix(const std::filesystem::path &prefix,
                 const std::filesystem::path &path) {
    auto prefix_part = prefix.begin();
    auto path_part = path.begin();
    while (prefix_part != prefix.end() && path_part != path.end() &&
           *prefix_part == *path_part) {
        ++prefix_part;
        ++path_part;
    }
    return prefix_part == prefix.end();
}

void validate_empty_real_directory(const std::filesystem::path &directory,
                                   const char *label) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_empty(directory)) {
        throw std::invalid_argument(std::string(label) +
                                    " must be an empty real directory");
    }
}

bool same_storage_device(const std::filesystem::path &left,
                         const std::filesystem::path &right) {
#ifdef _WIN32
    // Canonical absolute paths on the same drive or UNC share a root name.
    return left.root_name() == right.root_name();
#else
    struct stat left_status {};
    struct stat right_status {};
    if (::stat(left.c_str(), &left_status) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to inspect BaseFold destination device", left,
            std::error_code(errno, std::generic_category()));
    }
    if (::stat(right.c_str(), &right_status) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to inspect BaseFold scratch device", right,
            std::error_code(errno, std::generic_category()));
    }
    return left_status.st_dev == right_status.st_dev;
#endif
}

class OutputRootCleanup {
  public:
    OutputRootCleanup(std::filesystem::path destination,
                      std::filesystem::path scratch)
        : roots_{std::move(destination), std::move(scratch)} {}

    OutputRootCleanup(const OutputRootCleanup &) = delete;
    OutputRootCleanup &operator=(const OutputRootCleanup &) = delete;

    ~OutputRootCleanup() {
        if (!armed_) {
            return;
        }
        for (const std::filesystem::path &root : roots_) {
            std::error_code error;
            std::filesystem::directory_iterator entry(root, error);
            const std::filesystem::directory_iterator end;
            while (!error && entry != end) {
                const std::filesystem::path child = entry->path();
                entry.increment(error);
                std::error_code ignored;
                std::filesystem::remove_all(child, ignored);
            }
        }
    }

    void clear() {
        for (const std::filesystem::path &root : roots_) {
            for (auto entry = std::filesystem::directory_iterator(root);
                 entry != std::filesystem::directory_iterator();) {
                const std::filesystem::path child = entry->path();
                ++entry;
                std::filesystem::remove_all(child);
            }
            if (!std::filesystem::is_empty(root)) {
                throw std::runtime_error(
                    "BaseFold output-root cleanup is incomplete");
            }
        }
        armed_ = false;
    }

    void disarm() { armed_ = false; }

  private:
    std::array<std::filesystem::path, 2> roots_;
    bool armed_ = true;
};

std::uint64_t directory_regular_bytes(
    const std::filesystem::path &directory) {
    std::uint64_t bytes = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            bytes = checked_add(bytes, entry.file_size(),
                                "scratch directory bytes");
        }
    }
    return bytes;
}

class MerkleFrontier {
  public:
    template <typename Emit>
    void push_postorder(const Digest &leaf, Emit emit) {
        Digest node = leaf;
        emit(node);
        std::size_t level = 0;
        while (level < occupied_.size() && occupied_[level]) {
            node = MerkleTree::hash_children(nodes_[level], node);
            emit(node);
            occupied_[level] = false;
            ++level;
        }
        if (level == occupied_.size()) {
            occupied_.push_back(false);
            nodes_.push_back({});
        }
        nodes_[level] = node;
        occupied_[level] = true;
        ++count_;
    }

    Digest finish(std::size_t expected_count) const {
        const std::size_t level = log2_exact(expected_count);
        if (count_ != expected_count || level >= occupied_.size() ||
            !occupied_[level] ||
            std::count(occupied_.begin(), occupied_.end(), true) != 1) {
            throw std::logic_error("incomplete external Merkle frontier");
        }
        return nodes_[level];
    }

  private:
    std::vector<Digest> nodes_;
    std::vector<bool> occupied_;
    std::size_t count_ = 0;
};

struct ScratchArtifact {
    std::filesystem::path directory;
    laminate::Digest identity{};
    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    std::uint64_t physical_bytes = 0;
    std::size_t element_count = 0;
};

class ScratchTracker {
  public:
    ScratchTracker(std::filesystem::path root, std::uint64_t max_bytes,
                   std::uint64_t min_free_bytes,
                   BaseFoldExternalCommitReport &report)
        : root_(std::move(root)), max_bytes_(max_bytes),
          min_free_bytes_(min_free_bytes), report_(report) {}

    std::filesystem::path create_directory(std::string name) const {
        if (name.empty() || name.find('/') != std::string::npos ||
            name.find('\\') != std::string::npos) {
            throw std::invalid_argument("invalid BaseFold scratch name");
        }
        const std::filesystem::path directory = root_ / std::move(name);
        if (!std::filesystem::create_directory(directory)) {
            throw std::runtime_error(
                "failed to create BaseFold scratch directory");
        }
        return directory;
    }

    storage::NativeFieldArtifactOptions next_limits() const {
        if (current_bytes_ >= max_bytes_) {
            throw std::runtime_error(
                "BaseFold commitment scratch quota exhausted");
        }
        return {
            .max_total_bytes = max_bytes_ - current_bytes_,
            .min_free_bytes = min_free_bytes_,
        };
    }

    void published(std::uint64_t physical_bytes) {
        current_bytes_ = checked_add(current_bytes_, physical_bytes,
                                     "live scratch bytes");
        if (current_bytes_ > max_bytes_) {
            throw std::logic_error("scratch writer exceeded its quota");
        }
        report_.scratch_written_physical_bytes = checked_add(
            report_.scratch_written_physical_bytes, physical_bytes,
            "written scratch bytes");
        report_.scratch_peak_physical_bytes = std::max(
            report_.scratch_peak_physical_bytes, current_bytes_);
    }

    void erase(const std::filesystem::path &directory,
               std::uint64_t expected_bytes) {
        const std::filesystem::path selected = normalized(directory);
        if (selected.parent_path() != root_ ||
            std::filesystem::is_symlink(
                std::filesystem::symlink_status(selected)) ||
            directory_regular_bytes(selected) != expected_bytes ||
            expected_bytes > current_bytes_) {
            throw std::runtime_error(
                "refusing to remove changed BaseFold scratch data");
        }
        std::filesystem::remove_all(selected);
        current_bytes_ -= expected_bytes;
        report_.scratch_deleted_physical_bytes = checked_add(
            report_.scratch_deleted_physical_bytes, expected_bytes,
            "deleted scratch bytes");
    }

    std::uint64_t current_bytes() const { return current_bytes_; }
    const std::filesystem::path &root() const { return root_; }

  private:
    std::filesystem::path root_;
    std::uint64_t max_bytes_ = 0;
    std::uint64_t min_free_bytes_ = 0;
    BaseFoldExternalCommitReport &report_;
    std::uint64_t current_bytes_ = 0;
};

constexpr std::size_t kCommitPhaseCount = 5;

std::size_t commit_phase_index(BaseFoldExternalCommitPhase phase) {
    return static_cast<std::size_t>(phase);
}

std::size_t balanced_factor_radix(std::size_t size,
                                  std::size_t radix_cap);

std::uint64_t factorized_mobius_passes(std::size_t size,
                                       std::size_t radix_cap) {
    if (size <= radix_cap) {
        return 1;
    }
    const std::size_t radix = balanced_factor_radix(size, radix_cap);
    return checked_add(
        3U, factorized_mobius_passes(size / radix, radix_cap),
        "factorized Mobius passes");
}

std::uint64_t factorized_ntt_passes(std::size_t size,
                                    std::size_t radix_cap) {
    if (size <= radix_cap) {
        return 1;
    }
    const std::size_t radix = balanced_factor_radix(size, radix_cap);
    return checked_add(
        4U, factorized_ntt_passes(size / radix, radix_cap),
        "factorized NTT passes");
}

struct CommitPassProgress {
    BaseFoldExternalCommitPhase phase =
        BaseFoldExternalCommitPhase::MobiusTransform;
    BaseFoldExternalCommitSubpass subpass =
        BaseFoldExternalCommitSubpass::SourceLocalMobius;
    BaseFoldExternalCommitWorkUnit work_unit =
        BaseFoldExternalCommitWorkUnit::FieldElements;
    std::size_t column_index = 0;
    std::uint64_t work_units = 0;
    std::uint64_t read_bytes = 0;
    std::uint64_t write_bytes = 0;
    std::uint64_t butterflies = 0;
    std::size_t radix_elements = 0;
    std::size_t row_count = 0;
    std::size_t row_size = 0;
};

class CommitProgressTracker {
  public:
    CommitProgressTracker(
        BaseFoldExternalCommitProgressCallback callback,
        std::size_t column_count,
        std::array<std::uint64_t, kCommitPhaseCount> phase_passes,
        std::array<std::uint64_t, kCommitPhaseCount> phase_read_bytes,
        std::array<std::uint64_t, kCommitPhaseCount> phase_write_bytes,
        std::array<std::uint64_t, kCommitPhaseCount> phase_butterflies)
        : callback_(std::move(callback)), column_count_(column_count),
          phase_passes_(phase_passes),
          phase_read_bytes_(phase_read_bytes),
          phase_write_bytes_(phase_write_bytes),
          phase_butterflies_(phase_butterflies) {
        for (std::size_t index = 0; index < kCommitPhaseCount; ++index) {
            total_passes_ = checked_add(total_passes_, phase_passes_[index],
                                        "commit progress passes");
        }
    }

    void begin_pass(CommitPassProgress pass) {
        if (active_ || pass.work_units == 0) {
            throw std::logic_error("invalid BaseFold progress pass start");
        }
        active_ = true;
        active_pass_ = pass;
        active_work_ = 0;
        active_reported_work_ = 0;
        active_read_bytes_ = 0;
        active_write_bytes_ = 0;
        active_butterflies_ = 0;
        recent_work_ = 0;
        recent_elapsed_milliseconds_ = 0;
        estimated_remaining_milliseconds_ = 0;
        active_quantum_ = std::max<std::uint64_t>(
            1U, (pass.work_units + 63U) / 64U);
        last_report_time_ = std::chrono::steady_clock::now();
        emit(BaseFoldExternalCommitProgressKind::PassStarted);
    }

    void advance(std::uint64_t work_units, std::uint64_t read_bytes,
                 std::uint64_t write_bytes,
                 std::uint64_t butterflies = 0) {
        if (!active_ || work_units > active_pass_.work_units - active_work_ ||
            read_bytes > active_pass_.read_bytes - active_read_bytes_ ||
            write_bytes >
                active_pass_.write_bytes - active_write_bytes_ ||
            butterflies >
                active_pass_.butterflies - active_butterflies_) {
            throw std::logic_error("invalid BaseFold progress advance");
        }
        active_work_ += work_units;
        active_read_bytes_ += read_bytes;
        active_write_bytes_ += write_bytes;
        active_butterflies_ += butterflies;
        const std::size_t phase = commit_phase_index(active_pass_.phase);
        phase_completed_read_bytes_[phase] = checked_add(
            phase_completed_read_bytes_[phase], read_bytes,
            "commit phase completed read bytes");
        phase_completed_write_bytes_[phase] = checked_add(
            phase_completed_write_bytes_[phase], write_bytes,
            "commit phase completed write bytes");
        phase_completed_butterflies_[phase] = checked_add(
            phase_completed_butterflies_[phase], butterflies,
            "commit phase completed butterflies");
        if (active_work_ == active_pass_.work_units ||
            active_work_ - active_reported_work_ >= active_quantum_) {
            const auto now = std::chrono::steady_clock::now();
            recent_work_ = active_work_ - active_reported_work_;
            recent_elapsed_milliseconds_ = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - last_report_time_)
                    .count());
            estimated_remaining_milliseconds_ = estimate_remaining();
            active_reported_work_ = active_work_;
            last_report_time_ = now;
            emit(BaseFoldExternalCommitProgressKind::WorkAdvanced);
        }
    }

    void complete_pass() {
        if (!active_ || active_work_ != active_pass_.work_units ||
            active_read_bytes_ != active_pass_.read_bytes ||
            active_write_bytes_ != active_pass_.write_bytes ||
            active_butterflies_ != active_pass_.butterflies) {
            throw std::logic_error("incomplete BaseFold progress pass");
        }
        ++completed_passes_;
        const std::size_t phase = commit_phase_index(active_pass_.phase);
        ++phase_completed_passes_[phase];
        emit(BaseFoldExternalCommitProgressKind::PassCompleted);
        if (phase_completed_passes_[phase] == phase_passes_[phase]) {
            if (phase_completed_read_bytes_[phase] !=
                    phase_read_bytes_[phase] ||
                phase_completed_write_bytes_[phase] !=
                    phase_write_bytes_[phase] ||
                phase_completed_butterflies_[phase] !=
                    phase_butterflies_[phase]) {
                throw std::logic_error(
                    "BaseFold phase progress disagrees with its plan");
            }
            emit(BaseFoldExternalCommitProgressKind::PhaseCompleted);
        }
        active_ = false;
    }

  private:
    std::uint64_t estimate_remaining() const {
        if (recent_work_ == 0 || recent_elapsed_milliseconds_ == 0) {
            return 0;
        }
        const std::uint64_t remaining =
            active_pass_.work_units - active_work_;
        const __uint128_t estimate =
            static_cast<__uint128_t>(remaining) *
            recent_elapsed_milliseconds_ / recent_work_;
        return estimate > std::numeric_limits<std::uint64_t>::max()
                   ? std::numeric_limits<std::uint64_t>::max()
                   : static_cast<std::uint64_t>(estimate);
    }

    void emit(BaseFoldExternalCommitProgressKind kind) const noexcept {
        if (!callback_) {
            return;
        }
        const std::size_t phase = commit_phase_index(active_pass_.phase);
        try {
            callback_(BaseFoldExternalCommitProgress{
                .kind = kind,
                .phase = active_pass_.phase,
                .subpass = active_pass_.subpass,
                .work_unit = active_pass_.work_unit,
                .column_index = active_pass_.column_index,
                .column_count = column_count_,
                .completed_passes = completed_passes_,
                .total_passes = total_passes_,
                .phase_completed_passes = phase_completed_passes_[phase],
                .phase_total_passes = phase_passes_[phase],
                .pass_completed_work_units = active_work_,
                .pass_total_work_units = active_pass_.work_units,
                .pass_completed_read_bytes = active_read_bytes_,
                .pass_total_read_bytes = active_pass_.read_bytes,
                .pass_completed_write_bytes = active_write_bytes_,
                .pass_total_write_bytes = active_pass_.write_bytes,
                .phase_completed_read_bytes =
                    phase_completed_read_bytes_[phase],
                .phase_total_read_bytes = phase_read_bytes_[phase],
                .phase_completed_write_bytes =
                    phase_completed_write_bytes_[phase],
                .phase_total_write_bytes = phase_write_bytes_[phase],
                .pass_completed_butterflies = active_butterflies_,
                .pass_total_butterflies = active_pass_.butterflies,
                .phase_completed_butterflies =
                    phase_completed_butterflies_[phase],
                .phase_total_butterflies = phase_butterflies_[phase],
                .radix_elements = active_pass_.radix_elements,
                .row_count = active_pass_.row_count,
                .row_size = active_pass_.row_size,
                .recent_work_units = recent_work_,
                .recent_elapsed_milliseconds =
                    recent_elapsed_milliseconds_,
                .estimated_remaining_milliseconds =
                    estimated_remaining_milliseconds_,
            });
        } catch (...) {
            // Progress is diagnostic and cannot affect protocol behavior.
        }
    }

    BaseFoldExternalCommitProgressCallback callback_;
    std::size_t column_count_ = 0;
    std::array<std::uint64_t, kCommitPhaseCount> phase_passes_{};
    std::array<std::uint64_t, kCommitPhaseCount> phase_read_bytes_{};
    std::array<std::uint64_t, kCommitPhaseCount> phase_write_bytes_{};
    std::array<std::uint64_t, kCommitPhaseCount> phase_butterflies_{};
    std::array<std::uint64_t, kCommitPhaseCount> phase_completed_passes_{};
    std::array<std::uint64_t, kCommitPhaseCount>
        phase_completed_read_bytes_{};
    std::array<std::uint64_t, kCommitPhaseCount>
        phase_completed_write_bytes_{};
    std::array<std::uint64_t, kCommitPhaseCount>
        phase_completed_butterflies_{};
    std::uint64_t total_passes_ = 0;
    std::uint64_t completed_passes_ = 0;
    CommitPassProgress active_pass_;
    std::uint64_t active_work_ = 0;
    std::uint64_t active_reported_work_ = 0;
    std::uint64_t active_read_bytes_ = 0;
    std::uint64_t active_write_bytes_ = 0;
    std::uint64_t active_butterflies_ = 0;
    std::uint64_t active_quantum_ = 1;
    std::uint64_t recent_work_ = 0;
    std::uint64_t recent_elapsed_milliseconds_ = 0;
    std::uint64_t estimated_remaining_milliseconds_ = 0;
    std::chrono::steady_clock::time_point last_report_time_{};
    bool active_ = false;
};

void account_peak(BaseFoldExternalCommitReport &report,
                  const BaseFoldExternalCommitOptions &options,
                  std::uint64_t bytes) {
    report.peak_working_field_bytes =
        std::max(report.peak_working_field_bytes, bytes);
    if (bytes > options.max_working_field_bytes) {
        throw std::runtime_error(
            "BaseFold external commitment field-memory limit exceeded");
    }
}

void read_exact(storage::NativeFieldArrayReader &reader,
                std::span<Fq> output) {
    if (reader.read(output) != output.size()) {
        throw std::runtime_error("truncated BaseFold transform source");
    }
}

struct VirtualColumnPiece {
    std::size_t logical_begin = 0;
    std::size_t element_count = 0;
};

/// Forward-only logical view of one compact source column. Each stored value
/// is read once; omitted logical ranges are synthesized as zero.
class VirtualColumnReader {
  public:
    VirtualColumnReader(const storage::NativeFieldArtifact &source,
                        const BaseFoldArtifactColumn &column)
        : reader_(source.open_array(column.array_name)),
          logical_size_(checked_size(column.logical_evaluation_count,
                                     "logical column size")) {
        pieces_.reserve(column.segments.size());
        for (const BaseFoldArtifactColumnSegment &segment :
             column.segments) {
            pieces_.push_back({
                .logical_begin = checked_size(
                    segment.logical_begin, "logical segment begin"),
                .element_count = checked_size(
                    segment.element_count, "logical segment size"),
            });
        }
    }

    std::pair<std::uint64_t, std::uint64_t> read(std::span<Fq> output) {
        if (output.empty() || position_ > logical_size_ ||
            output.size() > logical_size_ - position_) {
            throw std::logic_error("invalid virtual BaseFold source read");
        }
        std::fill(output.begin(), output.end(), Fq::zero());
        const std::size_t end = position_ + output.size();
        std::uint64_t stored = 0;
        std::uint64_t operations = 0;
        while (piece_index_ < pieces_.size()) {
            const VirtualColumnPiece &piece = pieces_[piece_index_];
            const std::size_t piece_end =
                piece.logical_begin + piece.element_count;
            if (piece_end <= position_) {
                if (piece_consumed_ != piece.element_count) {
                    throw std::logic_error(
                        "virtual BaseFold source skipped a segment");
                }
                ++piece_index_;
                piece_consumed_ = 0;
                continue;
            }
            if (piece.logical_begin >= end) {
                break;
            }
            const std::size_t begin =
                std::max(position_, piece.logical_begin);
            const std::size_t overlap_end = std::min(end, piece_end);
            const std::size_t expected = begin - piece.logical_begin;
            if (piece_consumed_ != expected) {
                throw std::logic_error(
                    "virtual BaseFold source has a discontinuous segment: " +
                    std::to_string(piece_index_) + " consumed " +
                    std::to_string(piece_consumed_) + " expected " +
                    std::to_string(expected) + " position " +
                    std::to_string(position_) + " begin " +
                    std::to_string(piece.logical_begin));
            }
            const std::size_t count = overlap_end - begin;
            read_exact(reader_,
                       output.subspan(begin - position_, count));
            piece_consumed_ += count;
            stored = checked_add(stored, checked_u64(count, "stored read"),
                                 "stored source reads");
            operations = checked_add(operations, 1,
                                     "stored source read operations");
            if (piece_consumed_ == piece.element_count) {
                ++piece_index_;
                piece_consumed_ = 0;
            } else {
                break;
            }
        }
        position_ = end;
        return {stored, operations};
    }

  private:
    storage::NativeFieldArrayReader reader_;
    std::vector<VirtualColumnPiece> pieces_;
    std::size_t piece_index_ = 0;
    std::size_t piece_consumed_ = 0;
    std::size_t logical_size_ = 0;
    std::size_t position_ = 0;
};

bool dense_column(const BaseFoldArtifactColumn &column) {
    return column.segments.size() == 1 &&
           column.segments.front().logical_begin == 0 &&
           column.segments.front().stored_begin == 0 &&
           column.segments.front().element_count ==
               column.logical_evaluation_count;
}

ScratchArtifact publish_scratch_artifact(
    const std::filesystem::path &directory,
    const laminate::Digest &identity,
    storage::NativeFieldArtifactWriter &writer, std::size_t element_count,
    ScratchTracker &tracker, BaseFoldExternalCommitReport &report) {
    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    tracker.published(written.physical_bytes);
    report.positional_publication_read_bytes = checked_add(
        report.positional_publication_read_bytes,
        written.positional_publication_read_bytes,
        "positional publication read bytes");
    report.positional_publication_read_operations = checked_add(
        report.positional_publication_read_operations,
        written.positional_publication_read_operations,
        "positional publication read operations");
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        writer.trusted_finished_artifact());
    const storage::NativeFieldArrayDescriptor &values =
        artifact->array(kPassValuesArray);
    if (artifact->arrays().size() != 1 ||
        values.kind != storage::NativeFieldElementKind::Fq ||
        values.element_count != element_count) {
        throw std::logic_error("malformed BaseFold transform artifact");
    }
    return {directory, identity, std::move(artifact), written.physical_bytes,
            element_count};
}

std::size_t ceil_div(std::size_t numerator, std::size_t denominator) {
    if (denominator == 0) {
        throw std::invalid_argument("BaseFold block size is zero");
    }
    return numerator / denominator + (numerator % denominator != 0 ? 1U : 0U);
}

std::size_t floor_power_of_two(std::size_t value) {
    if (value == 0) {
        throw std::invalid_argument("BaseFold block size is zero");
    }
    return std::size_t{1} << (std::bit_width(value) - 1U);
}

/// Keep the two factors at one bit of each other whenever the explicit row
/// cap permits it. Once the remaining transform fits under that cap it stays
/// cache-local and creates no further external artifacts.
std::size_t balanced_factor_radix(std::size_t size,
                                  std::size_t radix_cap) {
    (void)log2_exact(size);
    (void)log2_exact(radix_cap);
    if (size <= radix_cap) {
        return size;
    }
    const std::size_t log_size = log2_exact(size);
    const std::size_t balanced =
        std::size_t{1} << ((log_size + 1U) / 2U);
    return std::min(radix_cap, balanced);
}

void mobius_rows_in_place(std::span<Fq> values) {
    (void)log2_exact(values.size());
    for (std::size_t bit = 1; bit < values.size(); bit <<= 1U) {
        for (std::size_t begin = 0; begin < values.size();
             begin += 2U * bit) {
            for (std::size_t offset = 0; offset < bit; ++offset) {
                values[begin + bit + offset] -= values[begin + offset];
            }
        }
    }
}

// The external transforms recurse over radix-sized rows. If n = a b and the
// input index is i = i_1 + b i_2, the NTT first computes the a transforms over
// i_2, applies omega^(i_1 k_2), then computes the b transforms over i_1. The
// surrounding transposes make each family of transforms sequential on disk
// and restore the natural output order k = k_2 + a k_1. Thus a recursive NTT
// level publishes four artifacts (three transposes and one local pass), while
// a recursive Mobius level publishes three (two transposes and one local
// pass). The base case publishes one cache-local pass through FqNttPlan; its
// backend dispatch remains separate from this readable factorization.

void account_cache_layers(BaseFoldExternalCommitReport &report,
                          std::size_t row_count,
                          std::size_t row_size) {
    report.cache_resident_butterfly_layers = checked_add(
        report.cache_resident_butterfly_layers,
        checked_multiply(checked_u64(row_count, "cache row count"),
                         checked_u64(log2_exact(row_size),
                                     "cache row logarithm"),
                         "cache-resident butterfly layers"),
        "cache-resident butterfly layers");
}

std::uint64_t fq_payload_bytes(std::size_t elements,
                               const char *label) {
    return checked_multiply(checked_u64(elements, label),
                            kSerializedFqBytes, label);
}

std::uint64_t row_butterflies(std::size_t row_size) {
    return checked_multiply(
        checked_u64(row_size / 2U, "butterflies per row"),
        checked_u64(log2_exact(row_size), "butterfly row logarithm"),
        "butterflies per row");
}

std::uint64_t local_butterflies(std::size_t row_count,
                                std::size_t row_size) {
    return checked_multiply(checked_u64(row_count, "butterfly row count"),
                            row_butterflies(row_size),
                            "local butterflies");
}

ScratchArtifact source_local_mobius_pass(
    const storage::NativeFieldArtifact &source,
    const BaseFoldArtifactColumn &column, std::size_t size,
    std::size_t row_size, const laminate::Digest &identity,
    std::string directory_name, ScratchTracker &tracker,
    BaseFoldExternalCommitReport &report, CommitProgressTracker &progress,
    std::size_t column_index) {
    if (row_size == 0 || size % row_size != 0) {
        throw std::invalid_argument("invalid source Mobius row shape");
    }
    const std::size_t row_count = size / row_size;
    progress.begin_pass({
        .phase = BaseFoldExternalCommitPhase::MobiusTransform,
        .subpass = BaseFoldExternalCommitSubpass::SourceLocalMobius,
        .work_unit = BaseFoldExternalCommitWorkUnit::FieldElements,
        .column_index = column_index,
        .work_units = checked_u64(size, "Mobius work"),
        .read_bytes = fq_payload_bytes(
            checked_size(source.array(column.array_name).element_count,
                         "source Mobius stored elements"),
            "source Mobius read bytes"),
        .write_bytes = fq_payload_bytes(size, "source Mobius write bytes"),
        .butterflies = local_butterflies(row_count, row_size),
        .radix_elements = row_size,
        .row_count = row_count,
        .row_size = row_size,
    });
    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    writer.begin_array(std::string(kPassValuesArray),
                       storage::NativeFieldElementKind::Fq,
                       checked_u64(size, "source Mobius size"));
    VirtualColumnReader reader(source, column);
    std::vector<Fq> row(row_size);
    std::uint64_t stored = 0;
    std::uint64_t read_operations = 0;
    for (std::size_t index = 0; index < row_count; ++index) {
        const auto [read, operations] = reader.read(row);
        stored = checked_add(stored, read, "source Mobius reads");
        read_operations = checked_add(
            read_operations, operations, "source Mobius read operations");
        mobius_rows_in_place(row);
        writer.append(row);
        progress.advance(
            checked_u64(row_size, "Mobius row work"),
            checked_multiply(read, kSerializedFqBytes,
                             "source Mobius row read bytes"),
            fq_payload_bytes(row_size, "source Mobius row write bytes"),
            row_butterflies(row_size));
    }
    writer.finish_array();
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes,
        checked_multiply(stored, kSerializedFqBytes,
                         "source Mobius read bytes"),
        "sequential read payload bytes");
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes,
        checked_multiply(checked_u64(size, "source Mobius size"),
                         kSerializedFqBytes, "source Mobius write bytes"),
        "sequential write payload bytes");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations, read_operations,
        "sequential read operations");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations,
        checked_u64(row_count, "source Mobius writes"),
        "sequential write operations");
    account_cache_layers(report, row_count, row_size);
    ++report.transform_pass_count;
    ScratchArtifact output = publish_scratch_artifact(
        directory, identity, writer, size, tracker, report);
    progress.complete_pass();
    return output;
}

ScratchArtifact local_mobius_pass(
    const storage::NativeFieldArtifact &input, std::string_view input_name,
    std::size_t size, std::size_t row_size,
    const laminate::Digest &identity, std::string directory_name,
    ScratchTracker &tracker, BaseFoldExternalCommitReport &report,
    CommitProgressTracker &progress, std::size_t column_index) {
    if (row_size == 0 || size % row_size != 0) {
        throw std::invalid_argument("invalid Mobius row shape");
    }
    const std::size_t row_count = size / row_size;
    const std::uint64_t bytes =
        fq_payload_bytes(size, "local Mobius bytes");
    progress.begin_pass({
        .phase = BaseFoldExternalCommitPhase::MobiusTransform,
        .subpass = BaseFoldExternalCommitSubpass::LocalMobius,
        .work_unit = BaseFoldExternalCommitWorkUnit::FieldElements,
        .column_index = column_index,
        .work_units = checked_u64(size, "Mobius work"),
        .read_bytes = bytes,
        .write_bytes = bytes,
        .butterflies = local_butterflies(row_count, row_size),
        .radix_elements = row_size,
        .row_count = row_count,
        .row_size = row_size,
    });
    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    writer.begin_array(std::string(kPassValuesArray),
                       storage::NativeFieldElementKind::Fq,
                       checked_u64(size, "local Mobius size"));
    storage::NativeFieldArrayReader reader = input.open_array(input_name);
    std::vector<Fq> row(row_size);
    for (std::size_t index = 0; index < row_count; ++index) {
        read_exact(reader, row);
        mobius_rows_in_place(row);
        writer.append(row);
        progress.advance(
            checked_u64(row_size, "Mobius row work"),
            fq_payload_bytes(row_size, "local Mobius row read bytes"),
            fq_payload_bytes(row_size, "local Mobius row write bytes"),
            row_butterflies(row_size));
    }
    writer.finish_array();
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes, bytes,
        "sequential read payload bytes");
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes, bytes,
        "sequential write payload bytes");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations,
        checked_u64(row_count, "local Mobius reads"),
        "sequential read operations");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations,
        checked_u64(row_count, "local Mobius writes"),
        "sequential write operations");
    account_cache_layers(report, row_count, row_size);
    ++report.transform_pass_count;
    ScratchArtifact output = publish_scratch_artifact(
        directory, identity, writer, size, tracker, report);
    progress.complete_pass();
    return output;
}

ScratchArtifact local_ntt_pass(
    const storage::NativeFieldArtifact &input, std::string_view input_name,
    std::size_t size, std::size_t row_size, std::size_t block_elements,
    const Fq &root,
    const laminate::Digest &identity, std::string directory_name,
    ScratchTracker &tracker, BaseFoldExternalCommitReport &report,
    CommitProgressTracker &progress, std::size_t column_index) {
    if (row_size == 0 || size % row_size != 0) {
        throw std::invalid_argument("invalid local NTT row shape");
    }
    const std::size_t row_count = size / row_size;
    const std::uint64_t butterflies =
        local_butterflies(row_count, row_size);
    const std::uint64_t bytes = fq_payload_bytes(size, "local NTT bytes");
    progress.begin_pass({
        .phase = BaseFoldExternalCommitPhase::NttTransform,
        .subpass = BaseFoldExternalCommitSubpass::LocalNtt,
        .work_unit = butterflies == 0
                         ? BaseFoldExternalCommitWorkUnit::FieldElements
                         : BaseFoldExternalCommitWorkUnit::NttButterflies,
        .column_index = column_index,
        .work_units = butterflies == 0
                          ? checked_u64(size, "NTT work")
                          : butterflies,
        .read_bytes = bytes,
        .write_bytes = bytes,
        .butterflies = butterflies,
        .radix_elements = row_size,
        .row_count = row_count,
        .row_size = row_size,
    });
    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    writer.begin_array(std::string(kPassValuesArray),
                       storage::NativeFieldElementKind::Fq,
                       checked_u64(size, "local NTT size"));
    storage::NativeFieldArrayReader reader = input.open_array(input_name);
    FqNttPlan plan(row_size, root);
    constexpr std::size_t kMinimumTransferElements = std::size_t{1} << 16U;
    const std::size_t transfer_elements = std::min(
        size, std::max(row_size,
                       std::min(block_elements, kMinimumTransferElements)));
    const std::size_t rows_per_transfer = transfer_elements / row_size;
    std::vector<Fq> rows(rows_per_transfer * row_size);
    for (std::size_t row_begin = 0; row_begin < row_count;
         row_begin += rows_per_transfer) {
        const std::size_t active_rows =
            std::min(rows_per_transfer, row_count - row_begin);
        std::span<Fq> active =
            std::span<Fq>(rows).first(active_rows * row_size);
        read_exact(reader, active);
        plan.apply_rows(active);
        writer.append(active);
        const std::uint64_t transfer_work = checked_multiply(
            checked_u64(active_rows, "NTT transfer row count"),
            row_butterflies(row_size), "NTT transfer butterflies");
        progress.advance(
            butterflies == 0
                ? checked_u64(active.size(), "NTT transfer work")
                : transfer_work,
            fq_payload_bytes(active.size(), "local NTT transfer read bytes"),
            fq_payload_bytes(active.size(),
                             "local NTT transfer write bytes"),
            transfer_work);
    }
    writer.finish_array();
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes, bytes,
        "sequential read payload bytes");
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes, bytes,
        "sequential write payload bytes");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations,
        checked_u64(ceil_div(row_count, rows_per_transfer),
                    "local NTT reads"),
        "sequential read operations");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations,
        checked_u64(ceil_div(row_count, rows_per_transfer),
                    "local NTT writes"),
        "sequential write operations");
    account_cache_layers(report, row_count, row_size);
    ++report.transform_pass_count;
    ScratchArtifact output = publish_scratch_artifact(
        directory, identity, writer, size, tracker, report);
    progress.complete_pass();
    return output;
}

ScratchArtifact pad_pass(
    const storage::NativeFieldArtifact &input, std::string_view input_name,
    std::size_t input_size, std::size_t output_size,
    std::size_t block_elements, const laminate::Digest &identity,
    std::string directory_name, ScratchTracker &tracker,
    BaseFoldExternalCommitReport &report, CommitProgressTracker &progress,
    std::size_t column_index) {
    progress.begin_pass({
        .phase = BaseFoldExternalCommitPhase::RateExpansion,
        .subpass = BaseFoldExternalCommitSubpass::RateExpansion,
        .work_unit = BaseFoldExternalCommitWorkUnit::FieldElements,
        .column_index = column_index,
        .work_units = checked_u64(output_size, "rate-expansion work"),
        .read_bytes = fq_payload_bytes(input_size,
                                       "rate-expansion read bytes"),
        .write_bytes = fq_payload_bytes(output_size,
                                        "rate-expansion write bytes"),
        .row_count = 1,
        .row_size = output_size,
    });
    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    writer.begin_array(std::string(kPassValuesArray),
                       storage::NativeFieldElementKind::Fq,
                       checked_u64(output_size, "padded pass size"));
    std::vector<Fq> buffer(block_elements, Fq::zero());
    storage::NativeFieldArrayReader reader = input.open_array(input_name);
    std::size_t copied = 0;
    while (copied < input_size) {
        const std::size_t count =
            std::min(block_elements, input_size - copied);
        read_exact(reader, std::span<Fq>(buffer).first(count));
        writer.append(std::span<const Fq>(buffer).first(count));
        copied += count;
        progress.advance(
            checked_u64(count, "rate-expansion copy work"),
            fq_payload_bytes(count, "rate-expansion copy read bytes"),
            fq_payload_bytes(count, "rate-expansion copy write bytes"));
    }
    std::fill(buffer.begin(), buffer.end(), Fq::zero());
    while (copied < output_size) {
        const std::size_t count =
            std::min(block_elements, output_size - copied);
        writer.append(std::span<const Fq>(buffer).first(count));
        copied += count;
        progress.advance(
            checked_u64(count, "rate-expansion zero work"), 0,
            fq_payload_bytes(count, "rate-expansion zero write bytes"));
    }
    writer.finish_array();
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes,
        checked_multiply(checked_u64(input_size, "pad input size"),
                         kSerializedFqBytes, "pad read bytes"),
        "sequential read payload bytes");
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes,
        checked_multiply(checked_u64(output_size, "pad output size"),
                         kSerializedFqBytes, "pad write bytes"),
        "sequential write payload bytes");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations,
        checked_u64(ceil_div(input_size, block_elements),
                    "pad read operations"),
        "sequential read operations");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations,
        checked_u64(ceil_div(input_size, block_elements) +
                        ceil_div(output_size - input_size, block_elements),
                    "pad write operations"),
        "sequential write operations");
    ++report.transform_pass_count;
    ScratchArtifact output = publish_scratch_artifact(
        directory, identity, writer, output_size, tracker, report);
    progress.complete_pass();
    return output;
}

std::pair<std::size_t, std::size_t> transpose_tile_shape(
    std::size_t rows, std::size_t columns, std::size_t block_elements) {
    const std::size_t available_bits =
        std::bit_width(floor_power_of_two(block_elements)) - 1U;
    const std::size_t row_bits = log2_exact(rows);
    const std::size_t column_bits = log2_exact(columns);
    std::size_t tile_row_bits = std::min(row_bits, available_bits / 2U);
    std::size_t tile_column_bits =
        std::min(column_bits, available_bits - tile_row_bits);
    std::size_t used = tile_row_bits + tile_column_bits;
    while (used < available_bits &&
           (tile_row_bits < row_bits ||
            tile_column_bits < column_bits)) {
        if (tile_row_bits < row_bits &&
            (tile_column_bits == column_bits ||
             tile_row_bits <= tile_column_bits)) {
            ++tile_row_bits;
        } else {
            ++tile_column_bits;
        }
        ++used;
    }
    return {std::size_t{1} << tile_row_bits,
            std::size_t{1} << tile_column_bits};
}

ScratchArtifact batched_transpose_pass(
    const storage::NativeFieldArtifact &input, std::string_view input_name,
    std::size_t batch_count, std::size_t rows, std::size_t columns,
    std::size_t block_elements, std::size_t radix_elements,
    const Fq *twiddle_root,
    const laminate::Digest &identity,
    std::string directory_name, ScratchTracker &tracker,
    BaseFoldExternalCommitReport &report,
    BaseFoldExternalCommitPhase progress_phase,
    CommitProgressTracker &progress, std::size_t column_index) {
    if (batch_count == 0 || rows == 0 || columns == 0 ||
        rows > std::numeric_limits<std::size_t>::max() / columns ||
        batch_count > std::numeric_limits<std::size_t>::max() /
                          (rows * columns)) {
        throw std::invalid_argument("invalid BaseFold transpose shape");
    }
    const std::size_t matrix_size = rows * columns;
    const std::size_t size = batch_count * matrix_size;
    const std::uint64_t payload_bytes =
        fq_payload_bytes(size, "transpose payload bytes");
    progress.begin_pass({
        .phase = progress_phase,
        .subpass = twiddle_root == nullptr
                       ? BaseFoldExternalCommitSubpass::Transpose
                       : BaseFoldExternalCommitSubpass::TwiddleTranspose,
        .work_unit = BaseFoldExternalCommitWorkUnit::FieldElements,
        .column_index = column_index,
        .work_units = checked_u64(size, "transpose work"),
        .read_bytes = payload_bytes,
        .write_bytes = payload_bytes,
        .radix_elements = radix_elements,
        .row_count = batch_count * rows,
        .row_size = columns,
    });
    const auto [tile_rows, tile_columns] =
        transpose_tile_shape(rows, columns, block_elements);
    const std::size_t tile_size = tile_rows * tile_columns;
    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    writer.begin_positional_fq_array(
        std::string(kPassValuesArray), checked_u64(size, "transpose size"));
    storage::NativeFieldArrayReader reader = input.open_array(input_name);
    std::vector<Fq> tile(tile_size);
    std::vector<Fq> transposed(tile_size);
    for (std::size_t batch = 0; batch < batch_count; ++batch) {
        const std::size_t batch_begin = batch * matrix_size;
        for (std::size_t row_begin = 0; row_begin < rows;
             row_begin += tile_rows) {
            for (std::size_t column_begin = 0; column_begin < columns;
                 column_begin += tile_columns) {
                for (std::size_t row = 0; row < tile_rows; ++row) {
                    reader.seek(batch_begin +
                                (row_begin + row) * columns +
                                column_begin);
                    read_exact(
                        reader,
                        std::span<Fq>(tile).subspan(
                            row * tile_columns, tile_columns));
                }
                if (twiddle_root != nullptr) {
                    apply_fq_twiddle_tile(
                        tile, tile_rows, tile_columns, row_begin,
                        column_begin, *twiddle_root);
                }
                transpose_fq_tile(tile, transposed, tile_rows,
                                  tile_columns);
                for (std::size_t column = 0; column < tile_columns;
                     ++column) {
                    const std::size_t output_index =
                        batch_begin +
                        (column_begin + column) * rows + row_begin;
                    writer.write_fq_at(
                        checked_u64(output_index, "transpose output index"),
                        std::span<const Fq>(transposed).subspan(
                            column * tile_rows, tile_rows));
                }
                const std::uint64_t tile_bytes =
                    fq_payload_bytes(tile_size, "transpose tile bytes");
                progress.advance(
                    checked_u64(tile_size, "transpose tile work"),
                    tile_bytes, tile_bytes);
            }
        }
    }
    writer.finish_array();
    const std::uint64_t read_operations = checked_multiply(
        checked_u64(size / tile_columns, "transpose read blocks"), 1U,
        "transpose read blocks");
    const std::uint64_t write_operations = checked_multiply(
        checked_u64(size / tile_rows, "transpose write blocks"), 1U,
        "transpose write blocks");
    report.indexed_read_payload_bytes = checked_add(
        report.indexed_read_payload_bytes, payload_bytes,
        "indexed read payload bytes");
    report.indexed_write_payload_bytes = checked_add(
        report.indexed_write_payload_bytes, payload_bytes,
        "indexed write payload bytes");
    report.indexed_read_operations = checked_add(
        report.indexed_read_operations, read_operations,
        "indexed read operations");
    report.indexed_write_operations = checked_add(
        report.indexed_write_operations, write_operations,
        "indexed write operations");
    report.read_seek_operations = checked_add(
        report.read_seek_operations, read_operations,
        "read seek operations");
    report.write_seek_operations = checked_add(
        report.write_seek_operations, write_operations,
        "write seek operations");
    report.peak_positional_coverage_intervals = std::max(
        report.peak_positional_coverage_intervals,
        checked_u64(tile_rows == rows ? 1U : columns,
                    "transpose coverage intervals"));
    ++report.transform_pass_count;
    ++report.transpose_pass_count;
    ScratchArtifact output = publish_scratch_artifact(
        directory, identity, writer, size, tracker, report);
    progress.complete_pass();
    return output;
}

void retire_scratch(ScratchArtifact &artifact, ScratchTracker &tracker) {
    const std::filesystem::path directory = artifact.directory;
    const std::uint64_t physical_bytes = artifact.physical_bytes;
    artifact.artifact.reset();
    tracker.erase(directory, physical_bytes);
    artifact = {};
}

ScratchArtifact transform_column(
    const storage::NativeFieldArtifact &source,
    const BaseFoldArtifactColumn &source_column,
    std::size_t column_index, std::size_t message_size,
    std::size_t codeword_size, std::size_t block_elements,
    std::size_t cache_radix_elements,
    const laminate::Digest &selection, ScratchTracker &tracker,
    BaseFoldExternalCommitReport &report, CommitProgressTracker &progress) {
    ScratchArtifact current;
    const storage::NativeFieldArtifact *input = &source;
    std::string input_name(source_column.array_name);
    std::size_t input_size = message_size;
    std::size_t pass = 0;
    const auto next_name = [&]() {
        return "column-" + std::to_string(column_index) + "-pass-" +
               std::to_string(pass);
    };
    const auto replace = [&](ScratchArtifact next) {
        if (current.artifact) {
            retire_scratch(current, tracker);
        }
        current = std::move(next);
        input = current.artifact.get();
        input_name = std::string(kPassValuesArray);
        input_size = current.element_count;
        ++pass;
    };

    const std::size_t radix_cap =
        floor_power_of_two(cache_radix_elements);
    const std::size_t first_mobius_radix =
        balanced_factor_radix(message_size, radix_cap);
    {
        const laminate::Digest identity = pass_identity(
            selection, column_index, pass, "mobius-local-source");
        replace(source_local_mobius_pass(
            source, source_column, message_size, first_mobius_radix,
            identity, next_name(), tracker, report, progress,
            column_index));
    }

    std::function<void(std::size_t, std::size_t)> factor_mobius;
    factor_mobius = [&](std::size_t batch_count,
                         std::size_t transform_size) {
        const std::size_t radix =
            balanced_factor_radix(transform_size, radix_cap);
        const std::size_t outer = transform_size / radix;
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "mobius-local");
            replace(local_mobius_pass(
                *input, input_name, message_size, radix, identity,
                next_name(), tracker, report, progress, column_index));
        }
        if (outer == 1) {
            return;
        }
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "mobius-transpose-in");
            replace(batched_transpose_pass(
                *input, input_name, batch_count, outer, radix,
                block_elements, radix, nullptr, identity, next_name(), tracker,
                report, BaseFoldExternalCommitPhase::MobiusTransform,
                progress, column_index));
        }
        factor_mobius(batch_count * radix, outer);
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "mobius-transpose-out");
            replace(batched_transpose_pass(
                *input, input_name, batch_count, radix, outer,
                block_elements, radix, nullptr, identity, next_name(), tracker,
                report, BaseFoldExternalCommitPhase::MobiusTransform,
                progress, column_index));
        }
    };
    const std::size_t remaining_mobius =
        message_size / first_mobius_radix;
    if (remaining_mobius != 1) {
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "mobius-transpose-in");
            replace(batched_transpose_pass(
                *input, input_name, 1, remaining_mobius,
                first_mobius_radix, block_elements, first_mobius_radix,
                nullptr, identity,
                next_name(), tracker, report,
                BaseFoldExternalCommitPhase::MobiusTransform, progress,
                column_index));
        }
        factor_mobius(first_mobius_radix, remaining_mobius);
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "mobius-transpose-out");
            replace(batched_transpose_pass(
                *input, input_name, 1, first_mobius_radix,
                remaining_mobius, block_elements, first_mobius_radix,
                nullptr, identity,
                next_name(), tracker, report,
                BaseFoldExternalCommitPhase::MobiusTransform, progress,
                column_index));
        }
    }
    if (codeword_size != input_size) {
        const laminate::Digest identity =
            pass_identity(selection, column_index, pass, "pad");
        replace(pad_pass(*input, input_name, input_size, codeword_size,
                         block_elements, identity, next_name(), tracker,
                         report, progress, column_index));
    }
    std::function<void(std::size_t, std::size_t, Fq)> factor_ntt;
    factor_ntt = [&](std::size_t batch_count, std::size_t transform_size,
                     Fq root) {
        const std::size_t radix =
            balanced_factor_radix(transform_size, radix_cap);
        const std::size_t outer = transform_size / radix;
        if (outer == 1) {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "ntt-local");
            replace(local_ntt_pass(
                *input, input_name, codeword_size, radix, block_elements,
                root, identity, next_name(), tracker, report, progress,
                column_index));
            return;
        }
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "ntt-transpose-in");
            replace(batched_transpose_pass(
                *input, input_name, batch_count, outer, radix,
                block_elements, radix, nullptr, identity, next_name(), tracker,
                report, BaseFoldExternalCommitPhase::NttTransform,
                progress, column_index));
        }
        factor_ntt(batch_count * radix, outer,
                   root.pow(checked_u64(radix, "NTT inner radix")));
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass,
                "ntt-twiddle-transpose");
            replace(batched_transpose_pass(
                *input, input_name, batch_count, radix, outer,
                block_elements, radix, &root, identity, next_name(), tracker,
                report, BaseFoldExternalCommitPhase::NttTransform,
                progress, column_index));
        }
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "ntt-local");
            replace(local_ntt_pass(
                *input, input_name, codeword_size, radix, block_elements,
                root.pow(checked_u64(outer, "NTT outer radix")), identity,
                next_name(), tracker, report, progress, column_index));
        }
        {
            const laminate::Digest identity = pass_identity(
                selection, column_index, pass, "ntt-transpose-out");
            replace(batched_transpose_pass(
                *input, input_name, batch_count, outer, radix,
                block_elements, radix, nullptr, identity, next_name(), tracker,
                report, BaseFoldExternalCommitPhase::NttTransform,
                progress, column_index));
        }
    };
    factor_ntt(1, codeword_size,
               Fq::two_adic_generator(log2_exact(codeword_size)));
    if (!current.artifact || current.element_count != codeword_size) {
        throw std::logic_error("BaseFold column transform is incomplete");
    }
    return current;
}

struct ScratchTree {
    ScratchArtifact storage;
    Digest root{};
};

ScratchTree build_interleaved_tree(
    std::span<const ScratchArtifact> codewords, std::size_t codeword_size,
    const laminate::Digest &selection,
    const BaseFoldExternalCommitOptions &options, ScratchTracker &tracker,
    BaseFoldExternalCommitReport &report, CommitProgressTracker &progress) {
    const std::size_t width = codewords.size();
    const std::size_t leaf_size = merkle_leaf_size(codeword_size);
    const std::size_t leaf_count = merkle_leaf_count(codeword_size);
    const std::size_t node_count = merkle_node_count(leaf_count);
    const std::uint64_t input_elements = checked_multiply(
        checked_u64(width, "Merkle width"),
        checked_u64(codeword_size, "Merkle codeword"),
        "Merkle input work");
    progress.begin_pass({
        .phase = BaseFoldExternalCommitPhase::MerkleTree,
        .subpass = BaseFoldExternalCommitSubpass::MerkleTree,
        .work_unit = BaseFoldExternalCommitWorkUnit::MerkleItems,
        .work_units = checked_add(input_elements,
                                  checked_u64(node_count, "Merkle node work"),
                                  "Merkle work"),
        .read_bytes = checked_multiply(input_elements, kSerializedFqBytes,
                                       "Merkle read bytes"),
        .write_bytes = checked_multiply(
            checked_u64(node_count, "Merkle node count"), Digest{}.size(),
            "Merkle write bytes"),
        .row_count = leaf_count,
        .row_size = leaf_size * width,
    });
    account_peak(
        report, options,
        checked_multiply(
            checked_multiply(checked_u64(leaf_size, "Merkle leaf size"),
                             checked_add(checked_u64(width, "column width"),
                                         1U, "Merkle staging width"),
                             "Merkle staging fields"),
            sizeof(Fq), "Merkle staging bytes"));

    std::vector<storage::NativeFieldArrayReader> readers;
    readers.reserve(width);
    for (const ScratchArtifact &codeword : codewords) {
        if (!codeword.artifact || codeword.element_count != codeword_size) {
            throw std::logic_error("malformed scratch codeword");
        }
        readers.push_back(codeword.artifact->open_array(kPassValuesArray));
    }

    const std::filesystem::path directory =
        tracker.create_directory("tree");
    const laminate::Digest identity = tree_identity(selection);
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    writer.begin_array(std::string(kScratchTreePostorderArray),
                       storage::NativeFieldElementKind::BaseFoldDigest,
                       checked_u64(node_count, "Merkle node count"));
    std::vector<Fq> column_values(leaf_size);
    std::vector<Fq> interleaved(leaf_size * width);
    std::vector<Digest> digests;
    digests.reserve(kDigestBufferElements);
    MerkleFrontier frontier;
    std::size_t written_nodes = 0;
    for (std::size_t leaf = 0; leaf < leaf_count; ++leaf) {
        const std::size_t previous_written_nodes = written_nodes;
        for (std::size_t column = 0; column < width; ++column) {
            read_exact(readers[column], column_values);
            for (std::size_t offset = 0; offset < leaf_size; ++offset) {
                interleaved[offset * width + column] = column_values[offset];
            }
        }
        frontier.push_postorder(MerkleTree::hash_fq_leaf(interleaved),
                                [&](const Digest &node) {
                                    digests.push_back(node);
                                    if (digests.size() ==
                                        kDigestBufferElements) {
                                        writer.append(digests);
                                        digests.clear();
                                    }
                                    ++written_nodes;
                                });
        const std::uint64_t leaf_elements = checked_multiply(
            checked_u64(width, "Merkle width"),
            checked_u64(leaf_size, "Merkle leaf size"),
            "Merkle leaf input work");
        const std::uint64_t emitted_nodes = checked_u64(
            written_nodes - previous_written_nodes, "Merkle emitted nodes");
        progress.advance(
            checked_add(leaf_elements, emitted_nodes, "Merkle leaf work"),
            checked_multiply(leaf_elements, kSerializedFqBytes,
                             "Merkle leaf read bytes"),
            checked_multiply(emitted_nodes, Digest{}.size(),
                             "Merkle leaf write bytes"));
    }
    if (!digests.empty()) {
        writer.append(digests);
    }
    if (written_nodes != node_count) {
        throw std::logic_error("external Merkle tree has the wrong size");
    }
    const Digest root = frontier.finish(leaf_count);
    writer.finish_array();
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes,
        checked_multiply(
            checked_multiply(checked_u64(width, "column width"),
                             checked_u64(codeword_size, "codeword size"),
                             "tree codeword fields"),
            kSerializedFqBytes, "tree codeword bytes"),
        "sequential read payload bytes");
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes,
        checked_multiply(checked_u64(node_count, "Merkle node count"),
                         Digest{}.size(), "tree write bytes"),
        "sequential write payload bytes");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations,
        checked_multiply(checked_u64(width, "column width"),
                         checked_u64(leaf_count, "Merkle leaf count"),
                         "tree read operations"),
        "sequential read operations");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations,
        checked_u64(ceil_div(node_count, kDigestBufferElements),
                    "tree write operations"),
        "sequential write operations");

    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    tracker.published(written.physical_bytes);
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        writer.trusted_finished_artifact());
    const storage::NativeFieldArrayDescriptor &tree =
        artifact->array(kScratchTreePostorderArray);
    if (artifact->arrays().size() != 1 ||
        tree.kind != storage::NativeFieldElementKind::BaseFoldDigest ||
        tree.element_count != node_count) {
        throw std::logic_error("malformed scratch Merkle artifact");
    }
    progress.complete_pass();
    return {{directory, identity, std::move(artifact), written.physical_bytes,
             node_count},
            root};
}

void copy_fq_array(
    const storage::NativeFieldArtifact &source, std::string_view source_name,
    std::string output_name, std::size_t count, std::size_t block_elements,
    storage::NativeFieldArtifactWriter &writer,
    BaseFoldExternalCommitReport &report, CommitProgressTracker &progress,
    std::size_t column_index, BaseFoldExternalCommitSubpass subpass) {
    const std::uint64_t bytes = fq_payload_bytes(count, "copied Fq bytes");
    progress.begin_pass({
        .phase = BaseFoldExternalCommitPhase::FinalPublication,
        .subpass = subpass,
        .work_unit = BaseFoldExternalCommitWorkUnit::FieldElements,
        .column_index = column_index,
        .work_units = checked_u64(count, "final Fq copy work"),
        .read_bytes = bytes,
        .write_bytes = bytes,
        .row_count = checked_size(ceil_div(count, block_elements),
                                  "final Fq block count"),
        .row_size = block_elements,
    });
    writer.begin_array(std::move(output_name),
                       storage::NativeFieldElementKind::Fq,
                       checked_u64(count, "copied Fq count"));
    storage::NativeFieldArrayReader reader = source.open_array(source_name);
    std::vector<Fq> buffer(block_elements);
    std::size_t copied = 0;
    while (copied < count) {
        const std::size_t take = std::min(block_elements, count - copied);
        read_exact(reader, std::span<Fq>(buffer).first(take));
        writer.append(std::span<const Fq>(buffer).first(take));
        copied += take;
        const std::uint64_t copied_bytes =
            fq_payload_bytes(take, "final Fq block bytes");
        progress.advance(checked_u64(take, "final Fq copy work"),
                         copied_bytes, copied_bytes);
    }
    writer.finish_array();
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes, bytes,
        "sequential read payload bytes");
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes, bytes,
        "sequential write payload bytes");
    const std::uint64_t operations = checked_u64(
        ceil_div(count, block_elements), "copied Fq operations");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations, operations,
        "sequential read operations");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations, operations,
        "sequential write operations");
    progress.complete_pass();
}

void copy_virtual_fq_array(
    const storage::NativeFieldArtifact &source,
    const BaseFoldArtifactColumn &column, std::string output_name,
    std::size_t count, std::size_t block_elements,
    storage::NativeFieldArtifactWriter &writer,
    BaseFoldExternalCommitReport &report, CommitProgressTracker &progress,
    std::size_t column_index) {
    progress.begin_pass({
        .phase = BaseFoldExternalCommitPhase::FinalPublication,
        .subpass = BaseFoldExternalCommitSubpass::MessagePublication,
        .work_unit = BaseFoldExternalCommitWorkUnit::FieldElements,
        .column_index = column_index,
        .work_units = checked_u64(count, "final virtual copy work"),
        .read_bytes = fq_payload_bytes(
            checked_size(source.array(column.array_name).element_count,
                         "final virtual stored elements"),
            "final virtual read bytes"),
        .write_bytes = fq_payload_bytes(count, "final virtual write bytes"),
        .row_count = checked_size(ceil_div(count, block_elements),
                                  "final virtual block count"),
        .row_size = block_elements,
    });
    writer.begin_array(std::move(output_name),
                       storage::NativeFieldElementKind::Fq,
                       checked_u64(count, "copied virtual Fq count"));
    VirtualColumnReader reader(source, column);
    std::vector<Fq> buffer(block_elements);
    std::size_t copied = 0;
    std::uint64_t stored = 0;
    std::uint64_t operations = 0;
    while (copied < count) {
        const std::size_t take = std::min(block_elements, count - copied);
        const auto [read, read_operations] =
            reader.read(std::span<Fq>(buffer).first(take));
        stored = checked_add(stored, read, "copied virtual source reads");
        operations = checked_add(operations, read_operations,
                                 "copied virtual source operations");
        writer.append(std::span<const Fq>(buffer).first(take));
        copied += take;
        progress.advance(
            checked_u64(take, "final virtual copy work"),
            checked_multiply(read, kSerializedFqBytes,
                             "final virtual block read bytes"),
            fq_payload_bytes(take, "final virtual block write bytes"));
    }
    writer.finish_array();
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes,
        checked_multiply(stored, kSerializedFqBytes,
                         "copied virtual source bytes"),
        "sequential read payload bytes");
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes,
        checked_multiply(checked_u64(count, "copied virtual Fq count"),
                         kSerializedFqBytes, "copied virtual Fq bytes"),
        "sequential write payload bytes");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations, operations,
        "sequential read operations");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations,
        checked_u64(ceil_div(count, block_elements),
                    "copied virtual Fq operations"),
        "sequential write operations");
    progress.complete_pass();
}

void copy_digest_array(
    const storage::NativeFieldArtifact &source, std::string_view source_name,
    std::string output_name, std::size_t count,
    storage::NativeFieldArtifactWriter &writer,
    BaseFoldExternalCommitReport &report, CommitProgressTracker &progress) {
    const std::uint64_t bytes = checked_multiply(
        checked_u64(count, "copied digest count"), Digest{}.size(),
        "copied digest bytes");
    progress.begin_pass({
        .phase = BaseFoldExternalCommitPhase::FinalPublication,
        .subpass = BaseFoldExternalCommitSubpass::MerklePublication,
        .work_unit = BaseFoldExternalCommitWorkUnit::MerkleItems,
        .work_units = checked_u64(count, "final digest copy work"),
        .read_bytes = bytes,
        .write_bytes = bytes,
        .row_count = checked_size(ceil_div(count, kDigestBufferElements),
                                  "final digest block count"),
        .row_size = kDigestBufferElements,
    });
    writer.begin_array(std::move(output_name),
                       storage::NativeFieldElementKind::BaseFoldDigest,
                       checked_u64(count, "copied digest count"));
    storage::NativeFieldArrayReader reader = source.open_array(source_name);
    std::array<Digest, kDigestBufferElements> buffer{};
    std::size_t copied = 0;
    while (copied < count) {
        const std::size_t take = std::min(buffer.size(), count - copied);
        if (reader.read(std::span<Digest>(buffer).first(take)) != take) {
            throw std::runtime_error("truncated Merkle tree scratch data");
        }
        writer.append(std::span<const Digest>(buffer).first(take));
        copied += take;
        const std::uint64_t copied_bytes = checked_multiply(
            checked_u64(take, "copied digest block count"), Digest{}.size(),
            "copied digest block bytes");
        progress.advance(checked_u64(take, "final digest copy work"),
                         copied_bytes, copied_bytes);
    }
    writer.finish_array();
    report.sequential_read_payload_bytes = checked_add(
        report.sequential_read_payload_bytes, bytes,
        "sequential read payload bytes");
    report.sequential_write_payload_bytes = checked_add(
        report.sequential_write_payload_bytes, bytes,
        "sequential write payload bytes");
    const std::uint64_t operations = checked_u64(
        ceil_div(count, kDigestBufferElements),
        "copied digest operations");
    report.sequential_read_operations = checked_add(
        report.sequential_read_operations, operations,
        "sequential read operations");
    report.sequential_write_operations = checked_add(
        report.sequential_write_operations, operations,
        "sequential write operations");
    progress.complete_pass();
}

} // namespace

BaseFoldExternalCommitStoragePlan BaseFoldPcs::plan_external_commit_storage(
    std::size_t logical_evaluation_count, std::size_t width,
    bool compact_columns, std::uint64_t max_working_field_bytes,
    std::size_t requested_block_elements,
    std::size_t requested_cache_radix_elements) const {
    if (logical_evaluation_count == 0 || width == 0) {
        throw std::invalid_argument(
            "BaseFold commitment planning needs nonzero dimensions");
    }
    if (max_working_field_bytes == 0 || requested_block_elements == 0) {
        throw std::invalid_argument(
            "BaseFold commitment planning needs nonzero memory limits");
    }
    (void)log2_exact(logical_evaluation_count);
    const std::size_t codeword_size = checked_codeword_size(
        logical_evaluation_count, parameters_.log_rate);
    if (codeword_size > 1 &&
        (requested_block_elements < 2 ||
         max_working_field_bytes < 4U * sizeof(Fq))) {
        throw std::invalid_argument(
            "BaseFold factorized commitment needs a two-element radix");
    }
    const std::size_t tree_nodes =
        merkle_node_count(merkle_leaf_count(codeword_size));
    std::vector<storage::NativeFieldArrayLayout> final_layout;
    final_layout.reserve(2U * width + 1U);
    for (std::size_t column = 0; column < width; ++column) {
        final_layout.push_back({
            message_array_name(column),
            storage::NativeFieldElementKind::Fq,
            checked_u64(logical_evaluation_count, "message size"),
        });
    }
    for (std::size_t column = 0; column < width; ++column) {
        final_layout.push_back({
            codeword_array_name(column),
            storage::NativeFieldElementKind::Fq,
            checked_u64(codeword_size, "codeword size"),
        });
    }
    final_layout.push_back({
        std::string(kBaseTreePostorderArray),
        storage::NativeFieldElementKind::BaseFoldDigest,
        checked_u64(tree_nodes, "Merkle node count"),
    });

    const std::array<storage::NativeFieldArrayLayout, 1> codeword_pass{{{
        std::string(kPassValuesArray),
        storage::NativeFieldElementKind::Fq,
        checked_u64(codeword_size, "codeword size"),
    }}};
    const std::array<storage::NativeFieldArrayLayout, 1> tree_layout{{{
        std::string(kScratchTreePostorderArray),
        storage::NativeFieldElementKind::BaseFoldDigest,
        checked_u64(tree_nodes, "Merkle node count"),
    }}};
    const std::uint64_t codeword_physical =
        storage::native_field_artifact_physical_bytes(codeword_pass);
    const std::uint64_t tree_physical =
        storage::native_field_artifact_physical_bytes(tree_layout);

    (void)compact_columns;
    const std::uint64_t completed_codewords = checked_multiply(
        checked_u64(width, "completed codeword count"), codeword_physical,
        "completed codeword scratch");
    const std::uint64_t transform_peak = checked_multiply(
        checked_add(checked_u64(width, "source width"), 1U,
                    "live transform artifacts"),
        codeword_physical, "live transform scratch");
    const std::uint64_t scratch_peak = std::max(
        transform_peak,
        checked_add(completed_codewords, tree_physical,
                    "live Merkle scratch"));
    const std::uint64_t merkle_staging_bytes = checked_multiply(
        checked_multiply(
            checked_u64(merkle_leaf_size(codeword_size),
                        "Merkle leaf size"),
            checked_add(checked_u64(width, "source width"), 1U,
                        "Merkle staging width"),
            "Merkle staging fields"),
        sizeof(Fq), "Merkle staging bytes");
    const std::uint64_t minimum_working_field_bytes = std::max(
        checked_u64((codeword_size == 1 ? 2U : 4U) * sizeof(Fq),
                    "minimum transform bytes"),
        merkle_staging_bytes);
    if (max_working_field_bytes < minimum_working_field_bytes) {
        throw std::invalid_argument(
            "BaseFold commitment field-memory limit is below its exact "
            "minimum");
    }
    const std::size_t memory_block_limit = checked_size(
        max_working_field_bytes / (2U * sizeof(Fq)),
        "field-memory block limit");
    const std::size_t block_elements = floor_power_of_two(std::min(
        {requested_block_elements, memory_block_limit, codeword_size}));
    const std::size_t requested_radix =
        requested_cache_radix_elements == 0
            ? std::min(block_elements,
                       kMaximumAutomaticCacheRadixElements)
            : requested_cache_radix_elements;
    const std::size_t cache_radix_elements = floor_power_of_two(std::min(
        {requested_radix, block_elements, codeword_size}));
    return {
        .final_physical_bytes =
            storage::native_field_artifact_physical_bytes(final_layout),
        .scratch_peak_physical_bytes = scratch_peak,
        .minimum_working_field_bytes = minimum_working_field_bytes,
        .effective_block_elements = block_elements,
        .effective_cache_radix_elements = cache_radix_elements,
        .peak_working_field_bytes = std::max(
            checked_multiply(
                checked_u64(block_elements, "transform block size"),
                2U * sizeof(Fq), "transform block bytes"),
            merkle_staging_bytes),
    };
}

BaseFoldExternalCommitment BaseFoldPcs::commit_artifact_columns(
    std::shared_ptr<const storage::NativeFieldArtifact> source,
    std::span<const std::string> source_array_names,
    BaseFoldExternalCommitOptions options) const {
    if (!source || source_array_names.empty()) {
        throw std::invalid_argument(
            "BaseFold external commitment needs source columns");
    }
    std::vector<BaseFoldArtifactColumn> columns;
    columns.reserve(source_array_names.size());
    for (const std::string &name : source_array_names) {
        const storage::NativeFieldArrayDescriptor &array =
            source->array(name);
        columns.push_back(BaseFoldArtifactColumn{
            .array_name = name,
            .logical_evaluation_count = array.element_count,
            .segments = {{.logical_begin = 0,
                          .stored_begin = 0,
                          .element_count = array.element_count}},
        });
    }
    return commit_artifact_columns(std::move(source), columns,
                                   std::move(options));
}

BaseFoldExternalCommitment BaseFoldPcs::commit_artifact_columns(
    std::shared_ptr<const storage::NativeFieldArtifact> source,
    std::span<const BaseFoldArtifactColumn> source_columns,
    BaseFoldExternalCommitOptions options) const {
    if (!source || source_columns.empty() ||
        options.max_final_bytes == 0 || options.max_scratch_bytes == 0 ||
        options.min_free_bytes == 0 ||
        options.max_working_field_bytes == 0 ||
        options.block_elements == 0) {
        throw std::invalid_argument(
            "BaseFold external commitment needs source columns and explicit "
            "nonzero limits");
    }
    const std::filesystem::path source_directory =
        normalized(source->directory());
    options.destination_directory = normalized(options.destination_directory);
    options.scratch_directory = normalized(options.scratch_directory);
    validate_empty_real_directory(options.destination_directory,
                                  "BaseFold destination");
    validate_empty_real_directory(options.scratch_directory,
                                  "BaseFold scratch root");
    const std::array<std::filesystem::path, 3> paths{
        source_directory,
        options.destination_directory,
        options.scratch_directory,
    };
    for (std::size_t left = 0; left < paths.size(); ++left) {
        for (std::size_t right = left + 1U; right < paths.size(); ++right) {
            if (path_prefix(paths[left], paths[right]) ||
                path_prefix(paths[right], paths[left])) {
                throw std::invalid_argument(
                    "BaseFold source, scratch, and destination must be "
                    "disjoint directories");
            }
        }
    }

    std::set<std::string> unique_names;
    std::size_t message_size = 0;
    std::uint64_t stored_source_elements = 0;
    for (const BaseFoldArtifactColumn &column : source_columns) {
        if (column.array_name.empty() ||
            !unique_names.insert(column.array_name).second) {
            throw std::invalid_argument(
                "BaseFold source column names must be nonempty and unique");
        }
        const storage::NativeFieldArrayDescriptor &array =
            source->array(column.array_name);
        if (array.kind != storage::NativeFieldElementKind::Fq ||
            array.encoded_element_bytes != kSerializedFqBytes ||
            array.element_count == 0 ||
            array.element_count >
                std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(
                "BaseFold source column is not a canonical Fq array");
        }
        const std::size_t count = checked_size(
            column.logical_evaluation_count,
            "BaseFold logical source column size");
        (void)log2_exact(count);
        if (message_size == 0) {
            message_size = count;
        } else if (count != message_size) {
            throw std::invalid_argument(
                "BaseFold source columns have different lengths");
        }

        std::uint64_t expected_stored_begin = 0;
        std::uint64_t previous_logical_end = 0;
        for (const BaseFoldArtifactColumnSegment &segment :
             column.segments) {
            if (segment.element_count == 0 ||
                segment.stored_begin != expected_stored_begin ||
                segment.logical_begin < previous_logical_end ||
                segment.logical_begin > column.logical_evaluation_count ||
                segment.element_count >
                    column.logical_evaluation_count -
                        segment.logical_begin) {
                throw std::invalid_argument(
                    "BaseFold compact source segments are not canonical");
            }
            expected_stored_begin = checked_add(
                expected_stored_begin, segment.element_count,
                "compact stored segment extent");
            previous_logical_end = checked_add(
                segment.logical_begin, segment.element_count,
                "compact logical segment extent");
        }
        if (expected_stored_begin != array.element_count) {
            throw std::invalid_argument(
                "BaseFold compact source does not cover its stored array");
        }
        stored_source_elements = checked_add(
            stored_source_elements, array.element_count,
            "stored source elements");
    }
    const std::size_t width = source_columns.size();
    const std::size_t codeword_size =
        checked_codeword_size(message_size, parameters_.log_rate);
    const std::size_t leaf_count = merkle_leaf_count(codeword_size);
    const std::size_t tree_nodes = merkle_node_count(leaf_count);

    BaseFoldExternalCommitReport report;
    report.source_artifact_physical_bytes = source->physical_bytes();
    report.selected_source_payload_bytes = checked_multiply(
        stored_source_elements,
        kSerializedFqBytes, "selected source payload bytes");
    const std::uint64_t message_payload_bytes = checked_multiply(
        checked_multiply(checked_u64(width, "source width"),
                         checked_u64(message_size, "message size"),
                         "logical message elements"),
        kSerializedFqBytes, "logical message payload bytes");
    const std::uint64_t codeword_payload_bytes = checked_multiply(
        checked_multiply(checked_u64(width, "source width"),
                         checked_u64(codeword_size, "codeword size"),
                         "codeword elements"),
        kSerializedFqBytes, "codeword payload bytes");
    const std::uint64_t tree_payload_bytes = checked_multiply(
        checked_u64(tree_nodes, "tree nodes"), Digest{}.size(),
        "tree payload bytes");
    report.final_payload_bytes = checked_add(
        checked_add(message_payload_bytes,
                    codeword_payload_bytes, "final field payload bytes"),
        tree_payload_bytes, "final payload bytes");
    std::vector<storage::NativeFieldArrayLayout> final_layout;
    final_layout.reserve(2U * width + 1U);
    for (std::size_t column = 0; column < width; ++column) {
        final_layout.push_back({
            message_array_name(column),
            storage::NativeFieldElementKind::Fq,
            checked_u64(message_size, "message size"),
        });
    }
    for (std::size_t column = 0; column < width; ++column) {
        final_layout.push_back({
            codeword_array_name(column),
            storage::NativeFieldElementKind::Fq,
            checked_u64(codeword_size, "codeword size"),
        });
    }
    final_layout.push_back({
        std::string(kBaseTreePostorderArray),
        storage::NativeFieldElementKind::BaseFoldDigest,
        checked_u64(tree_nodes, "Merkle node count"),
    });
    const std::uint64_t expected_final_physical =
        storage::native_field_artifact_physical_bytes(final_layout);
    if (options.max_final_bytes < expected_final_physical) {
        throw std::invalid_argument(
            "BaseFold final-artifact quota is below its exact physical size");
    }

    const std::array<storage::NativeFieldArrayLayout, 1> codeword_pass{{{
        std::string(kPassValuesArray),
        storage::NativeFieldElementKind::Fq,
        checked_u64(codeword_size, "codeword size"),
    }}};
    const std::array<storage::NativeFieldArrayLayout, 1> tree_layout{{{
        std::string(kScratchTreePostorderArray),
        storage::NativeFieldElementKind::BaseFoldDigest,
        checked_u64(tree_nodes, "Merkle node count"),
    }}};
    const std::uint64_t codeword_pass_physical =
        storage::native_field_artifact_physical_bytes(codeword_pass);
    const std::uint64_t tree_physical =
        storage::native_field_artifact_physical_bytes(tree_layout);
    const std::uint64_t completed_codewords = checked_multiply(
        checked_u64(width, "completed codeword count"),
        codeword_pass_physical, "completed codeword scratch");
    const std::uint64_t expected_scratch_peak = std::max(
        checked_multiply(
            checked_add(checked_u64(width, "source width"), 1U,
                        "live transform artifacts"),
            codeword_pass_physical, "live transform scratch"),
        checked_add(completed_codewords, tree_physical,
                    "live Merkle scratch"));
    if (options.max_scratch_bytes < expected_scratch_peak) {
        throw std::invalid_argument(
            "BaseFold scratch quota is below its exact physical peak");
    }
    const std::uint64_t scratch_required_free = checked_add(
        expected_scratch_peak, options.min_free_bytes,
        "scratch free-space preflight");
    const std::uint64_t final_required_free = checked_add(
        expected_final_physical, options.min_free_bytes,
        "final free-space preflight");
    const std::filesystem::space_info scratch_space =
        std::filesystem::space(options.scratch_directory);
    const std::filesystem::space_info final_space =
        std::filesystem::space(options.destination_directory);
    const bool shared_device = same_storage_device(
        options.destination_directory, options.scratch_directory);
    const std::uint64_t shared_required_free = checked_add(
        checked_add(expected_scratch_peak, expected_final_physical,
                    "shared-device commitment bytes"),
        options.min_free_bytes, "shared-device free-space preflight");
    if ((shared_device &&
         std::min(scratch_space.available, final_space.available) <
             shared_required_free) ||
        (!shared_device &&
         (scratch_space.available < scratch_required_free ||
          final_space.available < final_required_free))) {
        throw std::runtime_error(
            "BaseFold external commitment has insufficient free space");
    }

    const bool has_compact_column = std::any_of(
        source_columns.begin(), source_columns.end(),
        [](const BaseFoldArtifactColumn &column) {
            return !dense_column(column);
        });
    const BaseFoldExternalCommitStoragePlan resource_plan =
        plan_external_commit_storage(
            message_size, width, has_compact_column,
            options.max_working_field_bytes, options.block_elements,
            options.cache_radix_elements);
    const std::size_t block_elements =
        resource_plan.effective_block_elements;
    const std::size_t cache_radix_elements =
        resource_plan.effective_cache_radix_elements;
    account_peak(report, options,
                 resource_plan.peak_working_field_bytes);

    std::array<std::uint64_t, kCommitPhaseCount> progress_passes{};
    std::array<std::uint64_t, kCommitPhaseCount> progress_read_bytes{};
    std::array<std::uint64_t, kCommitPhaseCount> progress_write_bytes{};
    std::array<std::uint64_t, kCommitPhaseCount> progress_butterflies{};
    const std::uint64_t mobius_passes =
        factorized_mobius_passes(message_size, cache_radix_elements);
    const std::uint64_t ntt_passes =
        factorized_ntt_passes(codeword_size, cache_radix_elements);
    const std::uint64_t width_u64 = checked_u64(width, "progress width");
    const auto set_transform_progress = [&](
                                            BaseFoldExternalCommitPhase phase,
                                            std::uint64_t passes,
                                            std::size_t size,
                                            std::uint64_t first_read_bytes) {
        const std::size_t index = commit_phase_index(phase);
        progress_passes[index] = checked_multiply(
            passes, width_u64, "transform progress passes");
        const std::uint64_t pass_bytes = fq_payload_bytes(
            size, "transform progress pass bytes");
        progress_read_bytes[index] = checked_add(
            first_read_bytes,
            checked_multiply(progress_passes[index] - width_u64,
                             pass_bytes, "later transform read bytes"),
            "transform read bytes");
        progress_write_bytes[index] = checked_multiply(
            progress_passes[index], pass_bytes, "transform write bytes");
        progress_butterflies[index] = checked_multiply(
            checked_multiply(
                width_u64, checked_u64(size / 2U, "transform half size"),
                "transform half work"),
            checked_u64(log2_exact(size), "transform logarithm"),
            "transform butterflies");
    };
    set_transform_progress(BaseFoldExternalCommitPhase::MobiusTransform,
                           mobius_passes, message_size,
                           report.selected_source_payload_bytes);
    if (codeword_size != message_size) {
        const std::size_t index = commit_phase_index(
            BaseFoldExternalCommitPhase::RateExpansion);
        progress_passes[index] = width_u64;
        progress_read_bytes[index] = message_payload_bytes;
        progress_write_bytes[index] = codeword_payload_bytes;
    }
    set_transform_progress(BaseFoldExternalCommitPhase::NttTransform,
                           ntt_passes, codeword_size,
                           codeword_payload_bytes);
    const std::size_t merkle_index =
        commit_phase_index(BaseFoldExternalCommitPhase::MerkleTree);
    progress_passes[merkle_index] = 1;
    progress_read_bytes[merkle_index] = codeword_payload_bytes;
    progress_write_bytes[merkle_index] = tree_payload_bytes;
    const std::size_t publication_index =
        commit_phase_index(BaseFoldExternalCommitPhase::FinalPublication);
    progress_passes[publication_index] =
        checked_add(checked_multiply(width_u64, 2U, "final field arrays"),
                    2U, "final arrays and artifact publication");
    progress_read_bytes[publication_index] =
        checked_add(
            checked_add(report.selected_source_payload_bytes,
                        codeword_payload_bytes,
                        "final field publication read bytes"),
            checked_add(tree_payload_bytes, Digest{}.size(),
                        "final Merkle publication read bytes"),
            "final publication read bytes");
    progress_write_bytes[publication_index] = checked_add(
        checked_add(message_payload_bytes, codeword_payload_bytes,
                    "final field publication write bytes"),
        tree_payload_bytes, "final publication write bytes");
    CommitProgressTracker progress(options.progress, width, progress_passes,
                                   progress_read_bytes,
                                   progress_write_bytes,
                                   progress_butterflies);

    const laminate::Digest selection =
        selection_identity(*source, source_columns, parameters_);
    OutputRootCleanup output_cleanup(options.destination_directory,
                                     options.scratch_directory);
    try {
        ScratchTracker tracker(options.scratch_directory,
                               options.max_scratch_bytes,
                               options.min_free_bytes, report);
        std::vector<ScratchArtifact> codewords;
        codewords.reserve(width);
        for (std::size_t column = 0; column < width; ++column) {
            codewords.push_back(transform_column(
                *source, source_columns[column], column, message_size,
                codeword_size, block_elements, cache_radix_elements,
                selection, tracker, report, progress));
        }
        ScratchTree tree = build_interleaved_tree(
            codewords, codeword_size, selection, options, tracker, report,
            progress);

        const PcsCommitment commitment{
            .scheme = kSchemeIdentifier,
            .root = tree.root,
            .evaluation_count = checked_u64(message_size, "message size"),
            .width = checked_u64(width, "column width"),
            .log_rate = static_cast<std::uint32_t>(parameters_.log_rate),
            .query_count = static_cast<std::uint32_t>(parameters_.query_count),
        };
        const laminate::Digest final_identity =
            basefold_external_state_identity(commitment);
        storage::NativeFieldArtifactWriter final_writer(
            options.destination_directory,
            storage::NativeFieldArtifactOptions{
                .max_total_bytes = options.max_final_bytes,
                .min_free_bytes = options.min_free_bytes,
            },
            final_identity);
        for (std::size_t column = 0; column < width; ++column) {
            if (dense_column(source_columns[column])) {
                copy_fq_array(*source, source_columns[column].array_name,
                              message_array_name(column), message_size,
                              block_elements, final_writer, report, progress,
                              column,
                              BaseFoldExternalCommitSubpass::
                                  MessagePublication);
            } else {
                copy_virtual_fq_array(
                    *source, source_columns[column],
                    message_array_name(column), message_size,
                    block_elements, final_writer, report, progress, column);
            }
        }
        for (std::size_t column = 0; column < width; ++column) {
            copy_fq_array(*codewords[column].artifact, kPassValuesArray,
                          codeword_array_name(column), codeword_size,
                          block_elements, final_writer, report, progress,
                          column,
                          BaseFoldExternalCommitSubpass::
                              CodewordPublication);
            retire_scratch(codewords[column], tracker);
        }
        copy_digest_array(*tree.storage.artifact, kScratchTreePostorderArray,
                          std::string(kBaseTreePostorderArray), tree_nodes,
                          final_writer, report, progress);
        retire_scratch(tree.storage, tracker);
        progress.begin_pass({
            .phase = BaseFoldExternalCommitPhase::FinalPublication,
            .subpass = BaseFoldExternalCommitSubpass::ArtifactPublication,
            .work_unit = BaseFoldExternalCommitWorkUnit::PublicationSteps,
            .work_units = 1,
            .read_bytes = Digest{}.size(),
        });
        const storage::NativeFieldArtifactWriteResult final_written =
            final_writer.finish();
        if (final_written.physical_bytes != expected_final_physical ||
            report.scratch_peak_physical_bytes != expected_scratch_peak) {
            throw std::logic_error(
                "BaseFold commitment resource preflight disagrees with output");
        }
        report.final_physical_bytes = final_written.physical_bytes;
        report.indexed_read_payload_bytes = checked_add(
            report.indexed_read_payload_bytes, Digest{}.size(),
            "final root validation payload");
        report.indexed_read_operations = checked_add(
            report.indexed_read_operations, 1U,
            "indexed read operations");
        report.read_seek_operations = checked_add(
            report.read_seek_operations, 1U, "read seek operations");
        auto final_artifact =
            std::make_shared<storage::NativeFieldArtifact>(
                final_writer.trusted_finished_artifact());
        std::shared_ptr<const ProverState> prover_state =
            adopt_external_prover_state(std::move(final_artifact), commitment);
        progress.advance(1U, Digest{}.size(), 0);
        progress.complete_pass();

        BaseFoldExternalization externalization{
            .commitment = commitment,
            .prover_state = std::move(prover_state),
            .artifact_identity = final_identity,
            .report = {
                .physical_bytes = final_written.physical_bytes,
                .message_payload_bytes = message_payload_bytes,
                .codeword_payload_bytes = codeword_payload_bytes,
                .merkle_tree_payload_bytes = tree_payload_bytes,
            },
        };

        if (tracker.current_bytes() != 0 ||
            !std::filesystem::is_empty(tracker.root()) ||
            report.scratch_deleted_physical_bytes !=
                report.scratch_written_physical_bytes) {
            throw std::runtime_error(
                "BaseFold commitment scratch cleanup is incomplete");
        }
        output_cleanup.disarm();
        return {std::move(externalization), report};
    } catch (...) {
        const std::exception_ptr failure = std::current_exception();
        output_cleanup.clear();
        std::rethrow_exception(failure);
    }
}

} // namespace laminate::spartan
