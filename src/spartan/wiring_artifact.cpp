/// @file wiring_artifact.cpp
/// @brief Artifact-backed Spartan WiringCheck with virtual zero tails.

#include "laminate/spartan/wiring_artifact.hpp"

#include "laminate/field/serialization.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace laminate::spartan {
namespace {

constexpr std::string_view kWiringRoundLabel =
    "laminate/spartan/wiring-round/v2";
constexpr std::string_view kSelectionDomain =
    "LaminateImpl/SpartanWiringArtifactSelection/v1";
constexpr std::string_view kCheckpointDomain =
    "LaminateImpl/SpartanWiringArtifactCheckpoint/v1";
constexpr std::string_view kCheckpointMatrix = "matrix";
constexpr std::string_view kCheckpointAssignment = "assignment";

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
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument(
            "wiring sumcheck table is not a power of two");
    }
    return std::bit_width(value) - 1U;
}

std::size_t floor_power_of_two(std::size_t value) {
    if (value == 0) {
        throw std::invalid_argument("wiring sumcheck block size is zero");
    }
    return std::size_t{1} << (std::bit_width(value) - 1U);
}

bool zero_digest(const Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t value) { return value == 0; });
}

std::filesystem::path normalized_path(const std::filesystem::path &path) {
    if (path.empty()) {
        throw std::invalid_argument("wiring sumcheck path is empty");
    }
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(
            "wiring sumcheck path must be a real directory");
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

bool paths_overlap(const std::filesystem::path &left,
                   const std::filesystem::path &right) {
    return path_prefix(left, right) || path_prefix(right, left);
}

void validate_empty_real_directory(
    const std::filesystem::path &directory) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_empty(directory)) {
        throw std::invalid_argument(
            "wiring sumcheck scratch must be an empty real directory");
    }
}

void append_u64(std::vector<std::uint8_t> &output,
                std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(
            static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_string(std::vector<std::uint8_t> &output,
                   std::string_view value) {
    append_u64(output, checked_u64(value.size(), "identity string"));
    output.insert(output.end(), value.begin(), value.end());
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

void append_fq2(std::vector<std::uint8_t> &output, const Fq2 &value) {
    const SerializedFq2 encoded = serialize(value);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_array(std::vector<std::uint8_t> &output,
                  const storage::NativeFieldArtifact &artifact,
                  std::string_view name) {
    const storage::NativeFieldArrayDescriptor &array =
        artifact.array(name);
    append_string(output, name);
    append_u64(output, static_cast<std::uint64_t>(array.kind));
    append_u64(output, array.element_count);
    append_digest(output, array.file_digest);
}

Digest selection_identity(
    const storage::NativeFieldArtifact &matrix,
    const storage::NativeFieldArtifact &assignment,
    const WiringSumcheckArtifactArrays &names,
    const WiringAssignmentStorageLayout &assignment_layout,
    std::size_t half_size,
    const Fq2 &claimed_value) {
    std::vector<std::uint8_t> encoding(kSelectionDomain.begin(),
                                       kSelectionDomain.end());
    append_digest(encoding, matrix.identity());
    append_array(encoding, matrix, names.matrix_public);
    append_array(encoding, matrix, names.matrix_witness);
    append_digest(encoding, assignment.identity());
    append_array(encoding, assignment, names.assignment_public);
    append_array(encoding, assignment, names.assignment_witness);
    append_u64(encoding, checked_u64(half_size, "assignment half"));
    append_u64(encoding,
               checked_u64(assignment_layout.segments.size(),
                           "assignment segment count"));
    for (const WiringAssignmentStorageSegment &segment :
         assignment_layout.segments) {
        append_u64(encoding, segment.logical_begin);
        append_u64(encoding, segment.stored_begin);
        append_u64(encoding, segment.element_count);
    }
    append_fq2(encoding, claimed_value);
    return sha256(encoding);
}

Digest checkpoint_identity(const Digest &selection,
                           std::size_t element_count,
                           std::span<const Fq2> fixed_prefix) {
    std::vector<std::uint8_t> encoding(kCheckpointDomain.begin(),
                                       kCheckpointDomain.end());
    append_digest(encoding, selection);
    append_u64(encoding,
               checked_u64(element_count, "checkpoint element count"));
    append_u64(encoding,
               checked_u64(fixed_prefix.size(), "fixed prefix size"));
    for (const Fq2 &coordinate : fixed_prefix) {
        append_fq2(encoding, coordinate);
    }
    return sha256(encoding);
}

void read_exact(storage::NativeFieldArrayReader &reader,
                std::span<Fq> output) {
    if (reader.read(output) != output.size()) {
        throw std::runtime_error("truncated wiring Fq source");
    }
}

void read_exact(storage::NativeFieldArrayReader &reader,
                std::span<Fq2> output) {
    if (reader.read(output) != output.size()) {
        throw std::runtime_error("truncated wiring Fq2 source");
    }
}

struct SourceReadCount {
    std::uint64_t matrix_elements = 0;
    std::uint64_t assignment_elements = 0;
    std::uint64_t operations = 0;
};

struct Fq2Piece {
    std::size_t begin = 0;
    std::size_t count = 0;
    std::size_t consumed = 0;
    storage::NativeFieldArrayReader reader;

    Fq2Piece(std::size_t selected_begin, std::size_t selected_count,
             storage::NativeFieldArrayReader selected_reader)
        : begin(selected_begin), count(selected_count),
          reader(std::move(selected_reader)) {}
};

struct FqPiece {
    std::size_t begin = 0;
    std::size_t count = 0;
    std::size_t consumed = 0;
    storage::NativeFieldArrayReader reader;

    FqPiece(std::size_t selected_begin, std::size_t selected_count,
            storage::NativeFieldArrayReader selected_reader)
        : begin(selected_begin), count(selected_count),
          reader(std::move(selected_reader)) {}
};

struct VirtualWitnessPiece {
    std::size_t begin = 0;
    std::size_t count = 0;
};

/// Sequential view of an arbitrary logical matrix segment. Stored public and
/// witness prefixes are spliced into the requested range; every other value
/// is synthesized as zero.
class MatrixSegmentReader {
  public:
    MatrixSegmentReader(const storage::NativeFieldArtifact &source,
                        std::string_view public_name,
                        std::string_view witness_name,
                        std::size_t half_size,
                        std::size_t public_count,
                        std::size_t witness_count,
                        std::size_t begin, std::size_t extent)
        : extent_(extent) {
        if (begin > 2U * half_size ||
            extent > 2U * half_size - begin) {
            throw std::logic_error("matrix segment is out of range");
        }
        add_piece(source, public_name, 0, public_count, begin, extent);
        add_piece(source, witness_name, half_size, witness_count,
                  begin, extent);
    }

    void read(std::span<Fq2> output, SourceReadCount &count) {
        if (output.empty() || position_ > extent_ ||
            output.size() > extent_ - position_) {
            throw std::logic_error("invalid matrix segment read");
        }
        std::fill(output.begin(), output.end(), Fq2::zero());
        const std::size_t end = position_ + output.size();
        for (Fq2Piece &piece : pieces_) {
            const std::size_t piece_end = piece.begin + piece.count;
            const std::size_t overlap_begin =
                std::max(position_, piece.begin);
            const std::size_t overlap_end = std::min(end, piece_end);
            if (overlap_begin >= overlap_end) {
                continue;
            }
            const std::size_t expected_consumed =
                overlap_begin - piece.begin;
            if (piece.consumed != expected_consumed) {
                throw std::logic_error(
                    "matrix segment reader lost sequential position");
            }
            const std::size_t values = overlap_end - overlap_begin;
            read_exact(piece.reader,
                       output.subspan(overlap_begin - position_, values));
            piece.consumed += values;
            count.matrix_elements = checked_add(
                count.matrix_elements, checked_u64(values, "matrix read"),
                "matrix source elements");
            count.operations = checked_add(
                count.operations, 1, "wiring source read operations");
        }
        position_ = end;
    }

  private:
    void add_piece(const storage::NativeFieldArtifact &source,
                   std::string_view name, std::size_t logical_begin,
                   std::size_t active_count, std::size_t segment_begin,
                   std::size_t segment_extent) {
        const std::size_t logical_end = logical_begin + active_count;
        const std::size_t segment_end = segment_begin + segment_extent;
        const std::size_t begin = std::max(logical_begin, segment_begin);
        const std::size_t end = std::min(logical_end, segment_end);
        if (begin >= end) {
            return;
        }
        storage::NativeFieldArrayReader reader = source.open_array(name);
        reader.seek(checked_u64(begin - logical_begin,
                                "matrix source seek"));
        pieces_.emplace_back(begin - segment_begin, end - begin,
                             std::move(reader));
    }

    std::vector<Fq2Piece> pieces_;
    std::size_t extent_ = 0;
    std::size_t position_ = 0;
};

/// Sequential view of an arbitrary logical assignment segment. The leading
/// one and public zero tail are virtual; the complete witness half is read
/// from its base-field artifact and lifted one block at a time.
class AssignmentSegmentReader {
  public:
    AssignmentSegmentReader(const storage::NativeFieldArtifact &source,
                            std::string_view public_name,
                            std::string_view witness_name,
                            std::size_t half_size,
                            std::size_t public_count,
                            std::span<const WiringAssignmentStorageSegment>
                                witness_segments,
                            std::size_t begin, std::size_t extent)
        : segment_begin_(begin), extent_(extent) {
        if (begin > 2U * half_size ||
            extent > 2U * half_size - begin) {
            throw std::logic_error("assignment segment is out of range");
        }
        public_piece_ = make_piece(
            source, public_name, 1, public_count, begin, extent);
        for (const WiringAssignmentStorageSegment &segment :
             witness_segments) {
            const std::size_t logical_begin =
                half_size + checked_size(
                                segment.logical_begin,
                                "witness segment logical begin");
            const std::size_t active_count = checked_size(
                segment.element_count, "witness segment size");
            const std::size_t logical_end = logical_begin + active_count;
            const std::size_t segment_end = begin + extent;
            const std::size_t overlap_begin =
                std::max(logical_begin, begin);
            const std::size_t overlap_end =
                std::min(logical_end, segment_end);
            if (overlap_begin >= overlap_end) {
                continue;
            }
            if (!witness_reader_.has_value()) {
                witness_reader_.emplace(source.open_array(witness_name));
                witness_reader_->seek(checked_u64(
                    checked_size(segment.stored_begin,
                                 "witness segment stored begin") +
                        overlap_begin - logical_begin,
                    "assignment source seek"));
            }
            witness_pieces_.push_back({
                .begin = overlap_begin - begin,
                .count = overlap_end - overlap_begin,
            });
        }
    }

    void read(std::span<Fq2> output, std::span<Fq> temporary,
              SourceReadCount &count) {
        if (output.empty() || temporary.size() < output.size() ||
            position_ > extent_ || output.size() > extent_ - position_) {
            throw std::logic_error("invalid assignment segment read");
        }
        std::fill(output.begin(), output.end(), Fq2::zero());
        const std::size_t global_begin = segment_begin_ + position_;
        if (global_begin == 0) {
            output.front() = Fq2::one();
        }
        const std::size_t end = position_ + output.size();
        if (public_piece_.has_value()) {
            FqPiece &piece = *public_piece_;
            const std::size_t piece_end = piece.begin + piece.count;
            const std::size_t overlap_begin =
                std::max(position_, piece.begin);
            const std::size_t overlap_end = std::min(end, piece_end);
            if (overlap_begin < overlap_end) {
                const std::size_t expected_consumed =
                    overlap_begin - piece.begin;
                if (piece.consumed != expected_consumed) {
                    throw std::logic_error(
                        "assignment segment reader lost sequential position");
                }
                const std::size_t values = overlap_end - overlap_begin;
                read_exact(piece.reader, temporary.first(values));
                const std::size_t output_begin = overlap_begin - position_;
                for (std::size_t index = 0; index < values; ++index) {
                    output[output_begin + index] =
                        Fq2::from_base(temporary[index]);
                }
                piece.consumed += values;
                count.assignment_elements = checked_add(
                    count.assignment_elements,
                    checked_u64(values, "assignment read"),
                    "assignment source elements");
                count.operations = checked_add(
                    count.operations, 1,
                    "wiring source read operations");
            }
        }
        while (witness_piece_index_ < witness_pieces_.size()) {
            const VirtualWitnessPiece &piece =
                witness_pieces_[witness_piece_index_];
            const std::size_t piece_end = piece.begin + piece.count;
            if (piece_end <= position_) {
                if (witness_piece_consumed_ != piece.count) {
                    throw std::logic_error(
                        "assignment witness reader lost sequential position");
                }
                ++witness_piece_index_;
                witness_piece_consumed_ = 0;
                continue;
            }
            if (piece.begin >= end) {
                break;
            }
            const std::size_t overlap_begin =
                std::max(position_, piece.begin);
            const std::size_t overlap_end = std::min(end, piece_end);
            const std::size_t expected_consumed =
                overlap_begin - piece.begin;
            if (witness_piece_consumed_ != expected_consumed ||
                !witness_reader_.has_value()) {
                throw std::logic_error(
                    "assignment witness reader lost sequential position");
            }
            const std::size_t values = overlap_end - overlap_begin;
            read_exact(*witness_reader_, temporary.first(values));
            const std::size_t output_begin = overlap_begin - position_;
            for (std::size_t index = 0; index < values; ++index) {
                output[output_begin + index] =
                    Fq2::from_base(temporary[index]);
            }
            witness_piece_consumed_ += values;
            count.assignment_elements = checked_add(
                count.assignment_elements,
                checked_u64(values, "assignment read"),
                "assignment source elements");
            count.operations = checked_add(
                count.operations, 1, "wiring source read operations");
            if (witness_piece_consumed_ == piece.count) {
                ++witness_piece_index_;
                witness_piece_consumed_ = 0;
            } else {
                break;
            }
        }
        position_ = end;
    }

  private:
    static std::optional<FqPiece> make_piece(
        const storage::NativeFieldArtifact &source,
        std::string_view name, std::size_t logical_begin,
        std::size_t active_count, std::size_t segment_begin,
        std::size_t segment_extent) {
        const std::size_t logical_end = logical_begin + active_count;
        const std::size_t segment_end = segment_begin + segment_extent;
        const std::size_t begin = std::max(logical_begin, segment_begin);
        const std::size_t end = std::min(logical_end, segment_end);
        if (begin >= end) {
            return std::nullopt;
        }
        storage::NativeFieldArrayReader reader = source.open_array(name);
        reader.seek(checked_u64(begin - logical_begin,
                                "assignment source seek"));
        return FqPiece(begin - segment_begin, end - begin,
                       std::move(reader));
    }

    std::optional<FqPiece> public_piece_;
    std::optional<storage::NativeFieldArrayReader> witness_reader_;
    std::vector<VirtualWitnessPiece> witness_pieces_;
    std::size_t witness_piece_index_ = 0;
    std::size_t witness_piece_consumed_ = 0;
    std::size_t segment_begin_ = 0;
    std::size_t extent_ = 0;
    std::size_t position_ = 0;
};

struct SourceGeometry {
    std::shared_ptr<const storage::NativeFieldArtifact> matrix;
    std::shared_ptr<const storage::NativeFieldArtifact> assignment;
    std::size_t half_size = 0;
    std::size_t public_inputs = 0;
    std::size_t matrix_public = 0;
    std::size_t matrix_witness = 0;
    std::size_t stored_witness = 0;
    WiringAssignmentStorageLayout assignment_layout;
};

void require_array(const storage::NativeFieldArrayDescriptor &array,
                   storage::NativeFieldElementKind kind,
                   const char *label) {
    if (array.kind != kind ||
        array.encoded_element_bytes != storage::encoded_element_bytes(kind) ||
        array.element_count == 0 ||
        array.element_count > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string(label) +
                                    " has the wrong field layout");
    }
}

SourceGeometry validate_sources(
    const std::filesystem::path &matrix_directory,
    const std::filesystem::path &assignment_directory,
    const WiringSumcheckArtifactArrays &names,
    const WiringAssignmentStorageLayout &requested_assignment_layout,
    const WiringSumcheckArtifactOptions &options,
    WiringSumcheckArtifactReport &report) {
    const std::array<std::string_view, 4> selected{
        names.matrix_public, names.matrix_witness,
        names.assignment_public, names.assignment_witness};
    if (std::any_of(selected.begin(), selected.end(),
                    [](std::string_view name) { return name.empty(); }) ||
        names.matrix_public == names.matrix_witness ||
        names.assignment_public == names.assignment_witness) {
        throw std::invalid_argument(
            "wiring source array names must be nonempty and distinct");
    }

    SourceGeometry geometry;
    geometry.matrix =
        std::make_shared<storage::NativeFieldArtifact>(
            storage::NativeFieldArtifact::open(
                matrix_directory,
                options.expected_matrix_identity));
    geometry.assignment =
        std::make_shared<storage::NativeFieldArtifact>(
            storage::NativeFieldArtifact::open(
                assignment_directory,
                options.expected_assignment_identity));
    report.matrix_artifact_physical_bytes = geometry.matrix->physical_bytes();
    report.assignment_artifact_physical_bytes =
        geometry.assignment->physical_bytes();
    report.source_validation_bytes = checked_add(
        report.matrix_artifact_physical_bytes,
        report.assignment_artifact_physical_bytes,
        "wiring source validation bytes");

    const auto &matrix_public =
        geometry.matrix->array(names.matrix_public);
    const auto &matrix_witness =
        geometry.matrix->array(names.matrix_witness);
    const auto &assignment_public =
        geometry.assignment->array(names.assignment_public);
    const auto &assignment_witness =
        geometry.assignment->array(names.assignment_witness);
    require_array(matrix_public,
                  storage::NativeFieldElementKind::Fq2,
                  "public matrix source");
    require_array(matrix_witness,
                  storage::NativeFieldElementKind::Fq2,
                  "witness matrix source");
    require_array(assignment_public,
                  storage::NativeFieldElementKind::Fq,
                  "public assignment source");
    require_array(assignment_witness,
                  storage::NativeFieldElementKind::Fq,
                  "witness assignment source");

    geometry.assignment_layout = requested_assignment_layout;
    if (geometry.assignment_layout.half_size == 0) {
        geometry.assignment_layout.half_size =
            assignment_witness.element_count;
        geometry.assignment_layout.segments = {{
            .logical_begin = 0,
            .stored_begin = 0,
            .element_count = assignment_witness.element_count,
        }};
    }
    geometry.half_size = checked_size(
        geometry.assignment_layout.half_size, "assignment half size");
    geometry.public_inputs = checked_size(
        assignment_public.element_count, "public input count");
    geometry.matrix_public = checked_size(
        matrix_public.element_count, "public matrix count");
    geometry.matrix_witness = checked_size(
        matrix_witness.element_count, "witness matrix count");
    std::uint64_t expected_stored_begin = 0;
    std::uint64_t previous_logical_end = 0;
    for (const WiringAssignmentStorageSegment &segment :
         geometry.assignment_layout.segments) {
        if (segment.element_count == 0 ||
            segment.stored_begin != expected_stored_begin ||
            segment.logical_begin < previous_logical_end ||
            segment.logical_begin >
                geometry.assignment_layout.half_size ||
            segment.element_count >
                geometry.assignment_layout.half_size -
                    segment.logical_begin) {
            throw std::invalid_argument(
                "compact wiring witness segments are not canonical");
        }
        expected_stored_begin = checked_add(
            expected_stored_begin, segment.element_count,
            "compact witness stored extent");
        previous_logical_end = checked_add(
            segment.logical_begin, segment.element_count,
            "compact witness logical extent");
    }
    if (expected_stored_begin != assignment_witness.element_count) {
        throw std::invalid_argument(
            "compact wiring witness does not cover its stored array");
    }
    geometry.stored_witness = checked_size(
        assignment_witness.element_count, "stored witness count");
    if (!std::has_single_bit(geometry.half_size) ||
        geometry.public_inputs >= geometry.half_size ||
        geometry.matrix_public != geometry.public_inputs + 1U ||
        geometry.matrix_witness > geometry.half_size ||
        geometry.half_size >
            std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::invalid_argument(
            "compact wiring sources have inconsistent logical dimensions");
    }

    report.selected_matrix_payload_bytes = checked_multiply(
        checked_add(matrix_public.element_count,
                    matrix_witness.element_count,
                    "selected matrix elements"),
        kSerializedFq2Bytes, "selected matrix payload");
    report.selected_assignment_payload_bytes = checked_multiply(
        checked_add(assignment_public.element_count,
                    checked_u64(geometry.stored_witness,
                                "stored witness count"),
                    "selected assignment elements"),
        kSerializedFqBytes, "selected assignment payload");
    report.selected_source_payload_bytes = checked_add(
        report.selected_matrix_payload_bytes,
        report.selected_assignment_payload_bytes,
        "selected wiring source payload");
    return geometry;
}

std::vector<MatrixSegmentReader> matrix_segments(
    const SourceGeometry &source,
    const WiringSumcheckArtifactArrays &names, std::size_t count,
    std::size_t extent, std::size_t offset_within_stride,
    std::size_t stride) {
    std::vector<MatrixSegmentReader> result;
    result.reserve(count);
    for (std::size_t prefix = 0; prefix < count; ++prefix) {
        result.emplace_back(
            *source.matrix, names.matrix_public, names.matrix_witness,
            source.half_size, source.matrix_public,
            source.matrix_witness,
            prefix * stride + offset_within_stride, extent);
    }
    return result;
}

std::vector<AssignmentSegmentReader> assignment_segments(
    const SourceGeometry &source,
    const WiringSumcheckArtifactArrays &names, std::size_t count,
    std::size_t extent, std::size_t offset_within_stride,
    std::size_t stride) {
    std::vector<AssignmentSegmentReader> result;
    result.reserve(count);
    for (std::size_t prefix = 0; prefix < count; ++prefix) {
        result.emplace_back(
            *source.assignment, names.assignment_public,
            names.assignment_witness, source.half_size,
            source.public_inputs, source.assignment_layout.segments,
            prefix * stride + offset_within_stride, extent);
    }
    return result;
}

void account_source_reads(WiringSumcheckArtifactReport &report,
                          const SourceReadCount &count,
                          const SourceGeometry &source) {
    const std::uint64_t expected_matrix = checked_add(
        checked_u64(source.matrix_public, "public matrix count"),
        checked_u64(source.matrix_witness, "witness matrix count"),
        "matrix source elements");
    const std::uint64_t expected_assignment = checked_add(
        checked_u64(source.public_inputs, "public input count"),
        checked_u64(source.stored_witness, "stored witness size"),
        "assignment source elements");
    if (count.matrix_elements != expected_matrix ||
        count.assignment_elements != expected_assignment) {
        throw std::logic_error(
            "wiring source pass did not consume each stored value once");
    }
    const std::uint64_t bytes = checked_add(
        checked_multiply(count.matrix_elements, kSerializedFq2Bytes,
                         "matrix source read bytes"),
        checked_multiply(count.assignment_elements, kSerializedFqBytes,
                         "assignment source read bytes"),
        "wiring source read bytes");
    report.source_read_payload_bytes = checked_add(
        report.source_read_payload_bytes, bytes,
        "all wiring source read bytes");
    report.source_read_operations = checked_add(
        report.source_read_operations, count.operations,
        "all wiring source read operations");
}

std::uint64_t field_payload_bytes(std::size_t count,
                                  std::size_t width,
                                  const char *label) {
    return checked_multiply(checked_u64(count, label),
                            checked_u64(width, "field payload width"),
                            label);
}

void account_field_payload(WiringSumcheckArtifactReport &report,
                           const WiringSumcheckArtifactOptions &options,
                           std::uint64_t bytes) {
    report.peak_working_field_bytes =
        std::max(report.peak_working_field_bytes, bytes);
    if (bytes > options.max_working_field_bytes) {
        throw std::runtime_error(
            "wiring sumcheck field-memory limit exceeded");
    }
}

std::uint64_t expected_field_peak(std::size_t domain_size,
                                  std::size_t source_rounds,
                                  std::size_t block_elements) {
    const std::size_t prefix_count = std::size_t{1} << source_rounds;
    const std::uint64_t retained_output_bytes = field_payload_bytes(
        log2_exact(domain_size), 3U * sizeof(Fq2),
        "wiring returned proof and point fields");
    const std::uint64_t prefix_bytes = field_payload_bytes(
        prefix_count, sizeof(Fq2), "wiring prefix field payload");
    std::uint64_t peak = retained_output_bytes;
    for (std::size_t round = 0; round < source_rounds; ++round) {
        const std::size_t suffix = domain_size >> (round + 1U);
        peak = std::max(
            peak,
            checked_add(
                retained_output_bytes,
                checked_add(
                    prefix_bytes,
                    field_payload_bytes(std::min(block_elements, suffix),
                                        5U * sizeof(Fq2) + sizeof(Fq),
                                        "wiring source-round fields"),
                    "wiring source-round working fields"),
                "wiring live source-round fields"));
    }
    const std::size_t checkpoint = domain_size / prefix_count;
    peak = std::max(
        peak,
        checked_add(
            retained_output_bytes,
            checked_add(
                prefix_bytes,
                field_payload_bytes(std::min(block_elements, checkpoint),
                                    2U * sizeof(Fq2) + sizeof(Fq),
                                    "wiring checkpoint fields"),
                "wiring checkpoint working fields"),
            "wiring live checkpoint fields"));
    for (std::size_t size = checkpoint; size > 1; size >>= 1U) {
        const std::size_t half = size / 2U;
        peak = std::max(
            peak,
            checked_add(
                retained_output_bytes,
                field_payload_bytes(std::min(block_elements, half),
                                    4U * sizeof(Fq2),
                                    "wiring fold-message fields"),
                "wiring live fold-message fields"));
        peak = std::max(
            peak,
            checked_add(
                retained_output_bytes,
                field_payload_bytes(std::min(block_elements, half),
                                    2U * sizeof(Fq2),
                                    "wiring fold-write fields"),
                "wiring live fold-write fields"));
    }
    return peak;
}

void expand_prefix_weights(std::vector<Fq2> &weights,
                           std::size_t &active,
                           const Fq2 &challenge) {
    if (active == 0 || active > weights.size() / 2U) {
        throw std::logic_error("wiring prefix table cannot expand");
    }
    for (std::size_t index = active; index-- > 0;) {
        const Fq2 previous = weights[index];
        const Fq2 high = previous * challenge;
        weights[2U * index] = previous - high;
        weights[2U * index + 1U] = high;
    }
    active *= 2U;
}

Fq2 evaluate_quadratic(const Fq2 &at_zero, const Fq2 &at_one,
                       const Fq2 &at_two, const Fq2 &point) {
    const Fq2 one = Fq2::one();
    const Fq2 two = one + one;
    const Fq2 inverse_two = Fq2::from_base(Fq(2).inverse());
    const Fq2 basis_zero = (point - one) * (point - two) * inverse_two;
    const Fq2 basis_one = Fq2::zero() - point * (point - two);
    const Fq2 basis_two = point * (point - one) * inverse_two;
    return at_zero * basis_zero + at_one * basis_one + at_two * basis_two;
}

void observe_round(const WiringSumcheckRound &round,
                   PublicCoin &public_coin) {
    std::array<std::uint8_t, 2U * kSerializedFq2Bytes> bytes{};
    const std::array<Fq2, 2> values{round.at_one, round.at_two};
    for (std::size_t index = 0; index < values.size(); ++index) {
        const SerializedFq2 encoded = serialize(values[index]);
        std::copy(encoded.begin(), encoded.end(),
                  bytes.begin() + static_cast<std::ptrdiff_t>(
                                      index * kSerializedFq2Bytes));
    }
    public_coin.observe(kWiringRoundLabel, bytes);
}

void advance_claim(Fq2 &claim, const Fq2 &challenge,
                   const WiringSumcheckRound &round) {
    const Fq2 at_zero = claim - round.at_one;
    claim = evaluate_quadratic(at_zero, round.at_one, round.at_two,
                               challenge);
}

WiringSumcheckRound evaluate_source_round(
    const SourceGeometry &source,
    const WiringSumcheckArtifactArrays &names,
    std::span<const Fq2> prefix_weights, std::size_t prefix_capacity,
    std::size_t variable, std::size_t domain_size,
    std::size_t block_elements, std::uint64_t retained_output_bytes,
    const WiringSumcheckArtifactOptions &options,
    WiringSumcheckArtifactReport &report) {
    const std::size_t suffix = domain_size >> (variable + 1U);
    const std::size_t block = std::min(block_elements, suffix);
    const std::size_t stride = 2U * suffix;
    account_field_payload(
        report, options,
        checked_add(
            retained_output_bytes,
            checked_add(
                field_payload_bytes(prefix_capacity, sizeof(Fq2),
                                    "wiring prefix fields"),
                field_payload_bytes(block,
                                    5U * sizeof(Fq2) + sizeof(Fq),
                                    "wiring source-round fields"),
                "wiring source-round working fields"),
            "wiring live source-round fields"));

    std::vector<MatrixSegmentReader> matrix_low = matrix_segments(
        source, names, prefix_weights.size(), suffix, 0, stride);
    std::vector<MatrixSegmentReader> matrix_high = matrix_segments(
        source, names, prefix_weights.size(), suffix, suffix, stride);
    std::vector<AssignmentSegmentReader> assignment_low =
        assignment_segments(source, names, prefix_weights.size(), suffix,
                            0, stride);
    std::vector<AssignmentSegmentReader> assignment_high =
        assignment_segments(source, names, prefix_weights.size(), suffix,
                            suffix, stride);

    std::vector<Fq2> matrix_zero(block);
    std::vector<Fq2> matrix_one(block);
    std::vector<Fq2> assignment_zero(block);
    std::vector<Fq2> assignment_one(block);
    std::vector<Fq2> input(block);
    std::vector<Fq> base_input(block);
    SourceReadCount reads;
    WiringSumcheckRound round;
    for (std::size_t block_begin = 0; block_begin < suffix;
         block_begin += block) {
        std::fill(matrix_zero.begin(), matrix_zero.end(), Fq2::zero());
        std::fill(matrix_one.begin(), matrix_one.end(), Fq2::zero());
        std::fill(assignment_zero.begin(), assignment_zero.end(),
                  Fq2::zero());
        std::fill(assignment_one.begin(), assignment_one.end(),
                  Fq2::zero());
        for (std::size_t prefix = 0; prefix < prefix_weights.size();
             ++prefix) {
            matrix_low[prefix].read(input, reads);
            for (std::size_t index = 0; index < block; ++index) {
                matrix_zero[index] += prefix_weights[prefix] * input[index];
            }
            matrix_high[prefix].read(input, reads);
            for (std::size_t index = 0; index < block; ++index) {
                matrix_one[index] += prefix_weights[prefix] * input[index];
            }
            assignment_low[prefix].read(input, base_input, reads);
            for (std::size_t index = 0; index < block; ++index) {
                assignment_zero[index] +=
                    prefix_weights[prefix] * input[index];
            }
            assignment_high[prefix].read(input, base_input, reads);
            for (std::size_t index = 0; index < block; ++index) {
                assignment_one[index] +=
                    prefix_weights[prefix] * input[index];
            }
        }
        for (std::size_t index = 0; index < block; ++index) {
            round.at_one += matrix_one[index] * assignment_one[index];
            const Fq2 matrix_two =
                matrix_one[index] + matrix_one[index] - matrix_zero[index];
            const Fq2 assignment_two = assignment_one[index] +
                                       assignment_one[index] -
                                       assignment_zero[index];
            round.at_two += matrix_two * assignment_two;
        }
    }
    account_source_reads(report, reads, source);
    return round;
}

class ScratchRootCleanup {
  public:
    explicit ScratchRootCleanup(std::filesystem::path root)
        : root_(std::move(root)) {}

    ScratchRootCleanup(const ScratchRootCleanup &) = delete;
    ScratchRootCleanup &operator=(const ScratchRootCleanup &) = delete;

    void register_directory(const std::filesystem::path &directory) {
        if (directory.parent_path() != root_ ||
            std::any_of(entries_.begin(), entries_.end(),
                        [&](const Entry &entry) {
                            return entry.directory == directory;
                        })) {
            throw std::logic_error(
                "invalid or duplicate wiring scratch registration");
        }
        entries_.push_back({directory, std::nullopt});
    }

    void published(
        const std::filesystem::path &directory,
        const storage::NativeFieldArtifactWriteResult &artifact) {
        Entry &entry = registered(directory);
        if (entry.artifact.has_value()) {
            throw std::logic_error(
                "wiring scratch was published more than once");
        }
        if (artifact.directory != directory || artifact.arrays.empty() ||
            artifact.physical_bytes == 0) {
            throw std::logic_error(
                "invalid wiring scratch publication");
        }
        entry.artifact = PublishedArtifact{
            artifact.identity, artifact.arrays, artifact.physical_bytes};
    }

    std::uint64_t erase(const std::filesystem::path &directory,
                        std::uint64_t physical_bytes) {
        const std::size_t index = registered_index(directory);
        const Entry &entry = entries_[index];
        if (!entry.artifact.has_value() ||
            entry.artifact->physical_bytes != physical_bytes) {
            throw std::runtime_error(
                "refusing to remove unrecognized wiring scratch data");
        }
        const std::uint64_t validation_bytes = remove_entry(entry);
        entries_.erase(entries_.begin() +
                       static_cast<std::ptrdiff_t>(index));
        return validation_bytes;
    }

    void clear() {
        while (!entries_.empty()) {
            remove_entry(entries_.back());
            entries_.pop_back();
        }
    }

    void disarm() {
        if (!entries_.empty()) {
            throw std::logic_error(
                "wiring scratch cleanup still owns live directories");
        }
    }

  private:
    struct PublishedArtifact {
        Digest identity{};
        std::vector<storage::NativeFieldArrayDescriptor> arrays;
        std::uint64_t physical_bytes = 0;
    };

    struct Entry {
        std::filesystem::path directory;
        std::optional<PublishedArtifact> artifact;
    };

    std::size_t registered_index(
        const std::filesystem::path &directory) const {
        const auto found = std::find_if(
            entries_.begin(), entries_.end(), [&](const Entry &entry) {
                return entry.directory == directory;
            });
        if (found == entries_.end()) {
            throw std::logic_error(
                "unknown wiring scratch directory registration");
        }
        return static_cast<std::size_t>(found - entries_.begin());
    }

    Entry &registered(const std::filesystem::path &directory) {
        return entries_[registered_index(directory)];
    }

    std::uint64_t remove_entry(const Entry &entry) const {
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(entry.directory);
        if (!std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status)) {
            throw std::runtime_error(
                "refusing to remove path-substituted wiring scratch data");
        }
        const std::filesystem::path selected =
            std::filesystem::canonical(entry.directory);
        if (selected.parent_path() != root_) {
            throw std::runtime_error(
                "refusing to remove changed wiring scratch data");
        }
        std::uint64_t validation_bytes = 0;
        if (entry.artifact.has_value()) {
            try {
                const storage::NativeFieldArtifact actual =
                    storage::NativeFieldArtifact::open(
                        selected, entry.artifact->identity);
                if (actual.arrays() != entry.artifact->arrays ||
                    actual.physical_bytes() !=
                        entry.artifact->physical_bytes) {
                    throw std::runtime_error(
                        "published wiring scratch metadata changed");
                }
            } catch (const std::exception &) {
                throw std::runtime_error(
                    "refusing to remove changed wiring scratch data");
            }
            validation_bytes = entry.artifact->physical_bytes;
            std::filesystem::remove_all(selected);
        } else {
            if (!std::filesystem::is_empty(selected)) {
                throw std::runtime_error(
                    "refusing to remove unrecognized wiring scratch data");
            }
            if (!std::filesystem::remove(selected)) {
                throw std::runtime_error(
                    "wiring scratch cleanup is incomplete");
            }
        }
        if (std::filesystem::exists(
                std::filesystem::symlink_status(entry.directory))) {
            throw std::runtime_error(
                "wiring scratch cleanup is incomplete");
        }
        return validation_bytes;
    }

    std::filesystem::path root_;
    std::vector<Entry> entries_;
};

struct ScratchArtifact {
    std::filesystem::path directory;
    Digest identity{};
    std::shared_ptr<const storage::NativeFieldArtifact> artifact;
    std::uint64_t physical_bytes = 0;
    std::size_t element_count = 0;
};

class ScratchTracker {
  public:
    ScratchTracker(std::filesystem::path root, std::uint64_t max_bytes,
                   std::uint64_t min_free_bytes,
                   ScratchRootCleanup &cleanup,
                   WiringSumcheckArtifactReport &report)
        : root_(std::move(root)), max_bytes_(max_bytes),
          min_free_bytes_(min_free_bytes), cleanup_(cleanup),
          report_(report) {}

    std::filesystem::path create_directory(std::string name) {
        if (name.empty() || name.find('/') != std::string::npos ||
            name.find('\\') != std::string::npos) {
            throw std::invalid_argument("invalid wiring scratch name");
        }
        const std::filesystem::path directory = root_ / std::move(name);
        if (!std::filesystem::create_directory(directory)) {
            throw std::runtime_error(
                "failed to create wiring scratch directory");
        }
        try {
            cleanup_.register_directory(directory);
        } catch (...) {
            const std::exception_ptr failure = std::current_exception();
            std::filesystem::remove(directory);
            std::rethrow_exception(failure);
        }
        return directory;
    }

    storage::NativeFieldArtifactOptions next_limits() const {
        if (current_bytes_ >= max_bytes_) {
            throw std::runtime_error("wiring scratch quota exhausted");
        }
        return {
            .max_total_bytes = max_bytes_ - current_bytes_,
            .min_free_bytes = min_free_bytes_,
        };
    }

    void published(
        const std::filesystem::path &directory,
        const storage::NativeFieldArtifactWriteResult &artifact) {
        const std::uint64_t next_bytes = checked_add(
            current_bytes_, artifact.physical_bytes,
            "live wiring scratch bytes");
        if (next_bytes > max_bytes_) {
            throw std::logic_error("wiring writer exceeded scratch quota");
        }
        cleanup_.published(directory, artifact);
        current_bytes_ = next_bytes;
        report_.scratch_written_physical_bytes = checked_add(
            report_.scratch_written_physical_bytes,
            artifact.physical_bytes,
            "written wiring scratch bytes");
        report_.scratch_peak_physical_bytes = std::max(
            report_.scratch_peak_physical_bytes, current_bytes_);
    }

    void erase(const ScratchArtifact &artifact) {
        if (artifact.physical_bytes > current_bytes_) {
            throw std::runtime_error(
                "refusing to remove changed wiring scratch data");
        }
        const std::uint64_t validation_bytes =
            cleanup_.erase(artifact.directory, artifact.physical_bytes);
        report_.scratch_artifact_validation_bytes = checked_add(
            report_.scratch_artifact_validation_bytes, validation_bytes,
            "wiring scratch cleanup validation bytes");
        current_bytes_ -= artifact.physical_bytes;
        report_.scratch_deleted_physical_bytes = checked_add(
            report_.scratch_deleted_physical_bytes, artifact.physical_bytes,
            "deleted wiring scratch bytes");
    }

    std::uint64_t current_bytes() const { return current_bytes_; }

  private:
    std::filesystem::path root_;
    std::uint64_t max_bytes_ = 0;
    std::uint64_t min_free_bytes_ = 0;
    ScratchRootCleanup &cleanup_;
    WiringSumcheckArtifactReport &report_;
    std::uint64_t current_bytes_ = 0;
};

void retire_scratch(ScratchArtifact &artifact, ScratchTracker &tracker) {
    artifact.artifact.reset();
    tracker.erase(artifact);
    artifact = {};
}

std::uint64_t scratch_physical_bytes(std::size_t element_count) {
    const std::array<storage::NativeFieldArrayLayout, 2> layout{{
        {std::string(kCheckpointMatrix),
         storage::NativeFieldElementKind::Fq2,
         checked_u64(element_count, "scratch matrix size")},
        {std::string(kCheckpointAssignment),
         storage::NativeFieldElementKind::Fq2,
         checked_u64(element_count, "scratch assignment size")},
    }};
    return storage::native_field_artifact_physical_bytes(layout);
}

struct ScratchPreflight {
    std::uint64_t peak_bytes = 0;
    std::uint64_t cumulative_bytes = 0;
};

ScratchPreflight scratch_preflight(std::size_t checkpoint_size) {
    ScratchPreflight result;
    std::uint64_t previous = 0;
    for (std::size_t size = checkpoint_size;; size >>= 1U) {
        const std::uint64_t current = scratch_physical_bytes(size);
        result.cumulative_bytes = checked_add(
            result.cumulative_bytes, current,
            "cumulative wiring scratch bytes");
        result.peak_bytes = std::max(
            result.peak_bytes,
            checked_add(previous, current, "peak wiring scratch bytes"));
        previous = current;
        if (size == 1) {
            break;
        }
    }
    return result;
}

std::uint64_t interval_read_operations(std::size_t begin,
                                       std::size_t count,
                                       std::size_t block) {
    if (block == 0 || begin > std::numeric_limits<std::size_t>::max() - count) {
        throw std::overflow_error(
            "wiring source read-operation geometry overflows");
    }
    if (count == 0) {
        return 0;
    }
    const std::size_t end = begin + count;
    const std::size_t first_block = begin / block;
    const std::size_t past_last_block =
        end / block + (end % block != 0 ? 1U : 0U);
    return checked_u64(past_last_block - first_block,
                       "wiring interval read operations");
}

std::uint64_t source_pass_operations(const SourceGeometry &source,
                                     std::size_t block) {
    std::uint64_t result = interval_read_operations(
        0, source.matrix_public, block);
    result = checked_add(
        result,
        interval_read_operations(source.half_size, source.matrix_witness,
                                 block),
        "wiring matrix read operations");
    result = checked_add(
        result,
        interval_read_operations(1, source.public_inputs, block),
        "wiring assignment read operations");
    for (const WiringAssignmentStorageSegment &segment :
         source.assignment_layout.segments) {
        result = checked_add(
            result,
            interval_read_operations(
                source.half_size +
                    checked_size(segment.logical_begin,
                                 "witness segment logical begin"),
                checked_size(segment.element_count,
                             "witness segment size"),
                block),
            "wiring source-pass read operations");
    }
    return result;
}

struct WiringIoPreflight {
    std::uint64_t source_read_payload_bytes = 0;
    std::uint64_t source_read_operations = 0;
    std::uint64_t scratch_read_payload_bytes = 0;
    std::uint64_t scratch_read_operations = 0;
    std::uint64_t scratch_write_payload_bytes = 0;
    std::uint64_t scratch_write_operations = 0;
};

WiringIoPreflight io_preflight(
    const SourceGeometry &source, std::size_t domain_size,
    std::size_t source_rounds, std::size_t checkpoint_size,
    std::size_t block_elements,
    const WiringSumcheckArtifactReport &report) {
    WiringIoPreflight result;
    result.source_read_payload_bytes = checked_multiply(
        checked_u64(source_rounds + 1U, "wiring source passes"),
        report.selected_source_payload_bytes,
        "preflight wiring source read bytes");
    for (std::size_t variable = 0; variable < source_rounds; ++variable) {
        const std::size_t suffix = domain_size >> (variable + 1U);
        result.source_read_operations = checked_add(
            result.source_read_operations,
            source_pass_operations(source,
                                   std::min(block_elements, suffix)),
            "preflight wiring source read operations");
    }
    result.source_read_operations = checked_add(
        result.source_read_operations,
        source_pass_operations(
            source, std::min(block_elements, checkpoint_size)),
        "preflight wiring source read operations");

    const std::size_t first_block =
        std::min(block_elements, checkpoint_size);
    const std::uint64_t first_blocks = checked_u64(
        checkpoint_size / first_block, "wiring checkpoint blocks");
    result.scratch_write_payload_bytes = checked_multiply(
        checked_multiply(2U,
                         checked_u64(checkpoint_size,
                                     "wiring checkpoint size"),
                         "wiring checkpoint tables"),
        kSerializedFq2Bytes, "preflight wiring scratch write bytes");
    result.scratch_write_operations = checked_multiply(
        2U, first_blocks, "preflight wiring scratch write operations");

    for (std::size_t size = checkpoint_size; size > 1; size >>= 1U) {
        const std::size_t half = size / 2U;
        const std::size_t block = std::min(block_elements, half);
        const std::uint64_t blocks =
            checked_u64(half / block, "wiring fold blocks");
        result.scratch_read_payload_bytes = checked_add(
            result.scratch_read_payload_bytes,
            checked_multiply(
                checked_multiply(4U,
                                 checked_u64(size,
                                             "wiring fold source size"),
                                 "wiring fold read tables"),
                kSerializedFq2Bytes,
                "preflight wiring scratch read bytes"),
            "preflight all wiring scratch read bytes");
        result.scratch_read_operations = checked_add(
            result.scratch_read_operations,
            checked_multiply(8U, blocks,
                             "preflight wiring scratch read operations"),
            "preflight all wiring scratch read operations");
        result.scratch_write_payload_bytes = checked_add(
            result.scratch_write_payload_bytes,
            checked_multiply(
                checked_multiply(2U,
                                 checked_u64(half,
                                             "wiring fold output size"),
                                 "wiring fold output tables"),
                kSerializedFq2Bytes,
                "preflight wiring scratch write bytes"),
            "preflight all wiring scratch write bytes");
        result.scratch_write_operations = checked_add(
            result.scratch_write_operations,
            checked_multiply(2U, blocks,
                             "preflight wiring scratch write operations"),
            "preflight all wiring scratch write operations");
    }
    result.scratch_read_payload_bytes = checked_add(
        result.scratch_read_payload_bytes, 2U * kSerializedFq2Bytes,
        "preflight wiring terminal read bytes");
    result.scratch_read_operations = checked_add(
        result.scratch_read_operations, 2U,
        "preflight wiring terminal read operations");
    return result;
}

ScratchArtifact publish_scratch(
    const std::filesystem::path &directory, const Digest &identity,
    std::size_t element_count, storage::NativeFieldArtifactWriter &writer,
    ScratchTracker &tracker, WiringSumcheckArtifactReport &report) {
    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    tracker.published(directory, written);
    report.scratch_artifact_validation_bytes = checked_add(
        report.scratch_artifact_validation_bytes, written.physical_bytes,
        "wiring scratch validation bytes");
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(directory, identity));
    if (artifact->arrays().size() != 2) {
        throw std::logic_error("malformed wiring scratch artifact");
    }
    for (const std::string_view name :
         std::array<std::string_view, 2>{kCheckpointMatrix,
                                         kCheckpointAssignment}) {
        const auto &array = artifact->array(name);
        if (array.kind != storage::NativeFieldElementKind::Fq2 ||
            array.element_count != element_count) {
            throw std::logic_error("malformed wiring checkpoint array");
        }
    }
    return {directory, identity, std::move(artifact),
            written.physical_bytes, element_count};
}

ScratchArtifact materialize_checkpoint(
    const SourceGeometry &source,
    const WiringSumcheckArtifactArrays &names,
    std::span<const Fq2> prefix_weights, std::size_t prefix_capacity,
    std::size_t block_elements, const Digest &identity,
    std::string directory_name,
    std::uint64_t retained_output_bytes,
    const WiringSumcheckArtifactOptions &options, ScratchTracker &tracker,
    WiringSumcheckArtifactReport &report) {
    const std::size_t domain_size = 2U * source.half_size;
    const std::size_t checkpoint_size =
        domain_size / prefix_weights.size();
    const std::size_t block =
        std::min(block_elements, checkpoint_size);
    account_field_payload(
        report, options,
        checked_add(
            retained_output_bytes,
            checked_add(
                field_payload_bytes(prefix_capacity, sizeof(Fq2),
                                    "wiring prefix fields"),
                field_payload_bytes(block,
                                    2U * sizeof(Fq2) + sizeof(Fq),
                                    "wiring checkpoint fields"),
                "wiring checkpoint working fields"),
            "wiring live checkpoint fields"));

    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    std::vector<Fq2> output(block);
    std::vector<Fq2> input(block);
    std::vector<Fq> base_input(block);
    SourceReadCount reads;
    const std::size_t block_count = checkpoint_size / block;

    writer.begin_array(std::string(kCheckpointMatrix),
                       storage::NativeFieldElementKind::Fq2,
                       checked_u64(checkpoint_size,
                                   "matrix checkpoint size"));
    std::vector<MatrixSegmentReader> matrix = matrix_segments(
        source, names, prefix_weights.size(), checkpoint_size, 0,
        checkpoint_size);
    for (std::size_t block_index = 0; block_index < block_count;
         ++block_index) {
        std::fill(output.begin(), output.end(), Fq2::zero());
        for (std::size_t prefix = 0; prefix < prefix_weights.size();
             ++prefix) {
            matrix[prefix].read(input, reads);
            for (std::size_t index = 0; index < block; ++index) {
                output[index] += prefix_weights[prefix] * input[index];
            }
        }
        writer.append(output);
    }
    writer.finish_array();

    writer.begin_array(std::string(kCheckpointAssignment),
                       storage::NativeFieldElementKind::Fq2,
                       checked_u64(checkpoint_size,
                                   "assignment checkpoint size"));
    std::vector<AssignmentSegmentReader> assignment = assignment_segments(
        source, names, prefix_weights.size(), checkpoint_size, 0,
        checkpoint_size);
    for (std::size_t block_index = 0; block_index < block_count;
         ++block_index) {
        std::fill(output.begin(), output.end(), Fq2::zero());
        for (std::size_t prefix = 0; prefix < prefix_weights.size();
             ++prefix) {
            assignment[prefix].read(input, base_input, reads);
            for (std::size_t index = 0; index < block; ++index) {
                output[index] += prefix_weights[prefix] * input[index];
            }
        }
        writer.append(output);
    }
    writer.finish_array();
    account_source_reads(report, reads, source);
    report.scratch_write_payload_bytes = checked_add(
        report.scratch_write_payload_bytes,
        checked_multiply(
            checked_multiply(2U,
                             checked_u64(checkpoint_size,
                                         "checkpoint size"),
                             "checkpoint fields"),
            kSerializedFq2Bytes, "checkpoint write bytes"),
        "all wiring scratch write bytes");
    report.scratch_write_operations = checked_add(
        report.scratch_write_operations,
        checked_multiply(2U, checked_u64(block_count, "checkpoint blocks"),
                         "checkpoint write operations"),
        "all wiring scratch write operations");
    return publish_scratch(directory, identity, checkpoint_size, writer,
                           tracker, report);
}

WiringSumcheckRound evaluate_checkpoint_round(
    const ScratchArtifact &current, std::size_t block_elements,
    std::uint64_t retained_output_bytes,
    const WiringSumcheckArtifactOptions &options,
    WiringSumcheckArtifactReport &report) {
    const std::size_t half = current.element_count / 2U;
    const std::size_t block = std::min(block_elements, half);
    const std::size_t block_count = half / block;
    account_field_payload(
        report, options,
        checked_add(
            retained_output_bytes,
            field_payload_bytes(block, 4U * sizeof(Fq2),
                                "wiring fold-message fields"),
            "wiring live fold-message fields"));
    std::array<std::vector<Fq2>, 4> values;
    for (auto &buffer : values) {
        buffer.resize(block);
    }
    std::array<storage::NativeFieldArrayReader, 4> readers{
        current.artifact->open_array(kCheckpointMatrix),
        current.artifact->open_array(kCheckpointMatrix),
        current.artifact->open_array(kCheckpointAssignment),
        current.artifact->open_array(kCheckpointAssignment),
    };
    readers[1].seek(checked_u64(half, "matrix high checkpoint"));
    readers[3].seek(checked_u64(half, "assignment high checkpoint"));
    WiringSumcheckRound round;
    for (std::size_t block_index = 0; block_index < block_count;
         ++block_index) {
        for (std::size_t index = 0; index < readers.size(); ++index) {
            read_exact(readers[index], values[index]);
        }
        for (std::size_t index = 0; index < block; ++index) {
            round.at_one += values[1][index] * values[3][index];
            const Fq2 matrix_two =
                values[1][index] + values[1][index] - values[0][index];
            const Fq2 assignment_two =
                values[3][index] + values[3][index] - values[2][index];
            round.at_two += matrix_two * assignment_two;
        }
    }
    report.scratch_read_payload_bytes = checked_add(
        report.scratch_read_payload_bytes,
        checked_multiply(
            checked_multiply(2U,
                             checked_u64(current.element_count,
                                         "checkpoint elements"),
                             "checkpoint tables"),
            kSerializedFq2Bytes, "checkpoint message reads"),
        "all wiring scratch read bytes");
    report.scratch_read_operations = checked_add(
        report.scratch_read_operations,
        checked_multiply(4U, checked_u64(block_count, "checkpoint blocks"),
                         "checkpoint message operations"),
        "all wiring scratch read operations");
    return round;
}

ScratchArtifact fold_checkpoint(
    const ScratchArtifact &current, const Fq2 &challenge,
    std::size_t block_elements, const Digest &identity,
    std::string directory_name,
    std::uint64_t retained_output_bytes,
    const WiringSumcheckArtifactOptions &options, ScratchTracker &tracker,
    WiringSumcheckArtifactReport &report) {
    const std::size_t half = current.element_count / 2U;
    const std::size_t block = std::min(block_elements, half);
    const std::size_t block_count = half / block;
    account_field_payload(
        report, options,
        checked_add(
            retained_output_bytes,
            field_payload_bytes(block, 2U * sizeof(Fq2),
                                "wiring fold-write fields"),
            "wiring live fold-write fields"));
    const std::filesystem::path directory =
        tracker.create_directory(std::move(directory_name));
    storage::NativeFieldArtifactWriter writer(
        directory, tracker.next_limits(), identity);
    std::vector<Fq2> low(block);
    std::vector<Fq2> high(block);
    for (const std::string_view name :
         std::array<std::string_view, 2>{kCheckpointMatrix,
                                         kCheckpointAssignment}) {
        writer.begin_array(std::string(name),
                           storage::NativeFieldElementKind::Fq2,
                           checked_u64(half, "folded wiring size"));
        storage::NativeFieldArrayReader low_reader =
            current.artifact->open_array(name);
        storage::NativeFieldArrayReader high_reader =
            current.artifact->open_array(name);
        high_reader.seek(checked_u64(half, "wiring fold high segment"));
        for (std::size_t block_index = 0; block_index < block_count;
             ++block_index) {
            read_exact(low_reader, low);
            read_exact(high_reader, high);
            for (std::size_t index = 0; index < block; ++index) {
                low[index] += challenge * (high[index] - low[index]);
            }
            writer.append(low);
        }
        writer.finish_array();
    }
    const std::uint64_t payload = checked_multiply(
        checked_multiply(2U,
                         checked_u64(current.element_count,
                                     "fold source elements"),
                         "fold source tables"),
        kSerializedFq2Bytes, "fold source read bytes");
    report.scratch_read_payload_bytes = checked_add(
        report.scratch_read_payload_bytes, payload,
        "all wiring scratch read bytes");
    report.scratch_read_operations = checked_add(
        report.scratch_read_operations,
        checked_multiply(4U, checked_u64(block_count, "fold blocks"),
                         "fold read operations"),
        "all wiring scratch read operations");
    report.scratch_write_payload_bytes = checked_add(
        report.scratch_write_payload_bytes,
        checked_multiply(
            checked_multiply(2U, checked_u64(half, "fold output elements"),
                             "fold output tables"),
            kSerializedFq2Bytes, "fold write bytes"),
        "all wiring scratch write bytes");
    report.scratch_write_operations = checked_add(
        report.scratch_write_operations,
        checked_multiply(2U, checked_u64(block_count, "fold blocks"),
                         "fold write operations"),
        "all wiring scratch write operations");
    return publish_scratch(directory, identity, half, writer, tracker,
                           report);
}

std::array<Fq2, 2> read_terminal(
    const ScratchArtifact &current,
    WiringSumcheckArtifactReport &report) {
    if (current.element_count != 1) {
        throw std::logic_error("wiring terminal is not a singleton");
    }
    std::array<Fq2, 2> terminal{};
    const std::array<std::string_view, 2> names{
        kCheckpointMatrix, kCheckpointAssignment};
    for (std::size_t index = 0; index < names.size(); ++index) {
        storage::NativeFieldArrayReader reader =
            current.artifact->open_array(names[index]);
        read_exact(reader, std::span<Fq2>(&terminal[index], 1));
    }
    report.scratch_read_payload_bytes = checked_add(
        report.scratch_read_payload_bytes, 2U * kSerializedFq2Bytes,
        "wiring terminal read bytes");
    report.scratch_read_operations = checked_add(
        report.scratch_read_operations, 2U,
        "wiring terminal read operations");
    return terminal;
}

} // namespace

WiringSumcheckArtifactPlan plan_wiring_sumcheck_artifact(
    std::size_t half_size, std::size_t source_rounds,
    std::uint64_t max_working_field_bytes,
    std::size_t requested_block_elements) {
    if (!std::has_single_bit(half_size) ||
        half_size > std::numeric_limits<std::size_t>::max() / 2U ||
        max_working_field_bytes == 0 || requested_block_elements == 0 ||
        source_rounds > kDefaultArtifactWiringSourceRounds) {
        throw std::invalid_argument(
            "WiringCheck planning needs valid geometry and resources");
    }
    const std::size_t domain_size = 2U * half_size;
    const std::size_t variables = log2_exact(domain_size);
    const std::size_t effective_rounds =
        std::min(source_rounds, variables);
    const std::size_t checkpoint_size =
        domain_size / (std::size_t{1} << effective_rounds);
    const ScratchPreflight scratch = scratch_preflight(checkpoint_size);
    const std::uint64_t minimum_working_field_bytes =
        expected_field_peak(domain_size, effective_rounds, 1);
    if (max_working_field_bytes < minimum_working_field_bytes) {
        throw std::invalid_argument(
            "wiring field-memory limit cannot hold one block");
    }
    std::size_t block_elements = floor_power_of_two(
        std::min(requested_block_elements, domain_size));
    while (expected_field_peak(domain_size, effective_rounds,
                               block_elements) >
           max_working_field_bytes) {
        block_elements >>= 1U;
    }
    return {
        .scratch_peak_physical_bytes = scratch.peak_bytes,
        .scratch_written_physical_bytes = scratch.cumulative_bytes,
        .minimum_working_field_bytes = minimum_working_field_bytes,
        .effective_block_elements = block_elements,
        .peak_working_field_bytes = expected_field_peak(
            domain_size, effective_rounds, block_elements),
    };
}

std::uint64_t wiring_sumcheck_artifact_scratch_peak_physical_bytes(
    std::size_t half_size, std::size_t source_rounds) {
    if (!std::has_single_bit(half_size) ||
        half_size > std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::invalid_argument(
            "WiringCheck scratch planning needs a power-of-two half");
    }
    const std::size_t domain_size = 2U * half_size;
    const std::size_t variables = log2_exact(domain_size);
    const std::size_t effective_rounds =
        std::min(source_rounds, variables);
    return scratch_preflight(
               domain_size / (std::size_t{1} << effective_rounds))
        .peak_bytes;
}

WiringSumcheckArtifactOutput prove_wiring_sumcheck_artifact(
    const storage::NativeFieldArtifact &matrix_source,
    const storage::NativeFieldArtifact &assignment_source,
    const WiringSumcheckArtifactArrays &arrays,
    const Fq2 &claimed_value, PublicCoin &public_coin,
    WiringSumcheckArtifactOptions options) {
    return prove_wiring_sumcheck_artifact(
        matrix_source, assignment_source, arrays,
        WiringAssignmentStorageLayout{}, claimed_value, public_coin,
        std::move(options));
}

WiringSumcheckArtifactOutput prove_wiring_sumcheck_artifact(
    const storage::NativeFieldArtifact &matrix_source,
    const storage::NativeFieldArtifact &assignment_source,
    const WiringSumcheckArtifactArrays &arrays,
    const WiringAssignmentStorageLayout &assignment_layout,
    const Fq2 &claimed_value, PublicCoin &public_coin,
    WiringSumcheckArtifactOptions options) {
    if (zero_digest(options.expected_matrix_identity) ||
        zero_digest(options.expected_assignment_identity) ||
        options.scratch_directory.empty() ||
        options.max_live_storage_bytes == 0 ||
        options.max_total_scratch_bytes == 0 ||
        options.min_free_bytes == 0 ||
        options.max_working_field_bytes == 0 ||
        options.block_elements == 0 ||
        options.source_rounds > kDefaultArtifactWiringSourceRounds) {
        throw std::invalid_argument(
            "artifact WiringCheck needs explicit valid resources");
    }

    const std::filesystem::path matrix_directory =
        normalized_path(matrix_source.directory());
    const std::filesystem::path assignment_directory =
        normalized_path(assignment_source.directory());
    options.scratch_directory = normalized_path(options.scratch_directory);
    validate_empty_real_directory(options.scratch_directory);
    if (paths_overlap(matrix_directory, assignment_directory) ||
        paths_overlap(matrix_directory, options.scratch_directory) ||
        paths_overlap(assignment_directory, options.scratch_directory)) {
        throw std::invalid_argument(
            "wiring matrix, assignment, and scratch trees must be disjoint");
    }

    WiringSumcheckArtifactOutput output;
    const SourceGeometry source = validate_sources(
        matrix_directory, assignment_directory, arrays, assignment_layout,
        options,
        output.report);
    const std::size_t domain_size = 2U * source.half_size;
    const std::size_t variables = log2_exact(domain_size);
    const std::size_t source_rounds =
        std::min(options.source_rounds, variables);
    const std::size_t prefix_count = std::size_t{1} << source_rounds;
    const std::size_t checkpoint_size = domain_size / prefix_count;
    const WiringSumcheckArtifactPlan resource_plan =
        plan_wiring_sumcheck_artifact(
            source.half_size, source_rounds,
            options.max_working_field_bytes, options.block_elements);
    const ScratchPreflight scratch{
        .peak_bytes = resource_plan.scratch_peak_physical_bytes,
        .cumulative_bytes =
            resource_plan.scratch_written_physical_bytes,
    };
    const std::uint64_t expected_scratch_validation_bytes =
        checked_multiply(2U, scratch.cumulative_bytes,
                         "wiring scratch validation bytes");
    if (options.max_total_scratch_bytes < scratch.peak_bytes) {
        throw std::invalid_argument(
            "wiring scratch quota is below its exact physical peak");
    }
    output.report.peak_live_storage_bytes = checked_add(
        output.report.source_validation_bytes, scratch.peak_bytes,
        "peak live WiringCheck storage");
    if (output.report.peak_live_storage_bytes >
        options.max_live_storage_bytes) {
        throw std::invalid_argument(
            "WiringCheck live-storage quota is below its exact peak");
    }
    const std::uint64_t required_free = checked_add(
        scratch.peak_bytes, options.min_free_bytes,
        "wiring scratch free-space preflight");
    if (std::filesystem::space(options.scratch_directory).available <
        required_free) {
        throw std::runtime_error(
            "wiring sumcheck scratch has insufficient free space");
    }

    const std::size_t block_elements =
        resource_plan.effective_block_elements;
    const std::uint64_t exact_field_peak =
        resource_plan.peak_working_field_bytes;
    const std::uint64_t retained_output_bytes = field_payload_bytes(
        variables, 3U * sizeof(Fq2),
        "wiring returned proof and point fields");
    const WiringIoPreflight io = io_preflight(
        source, domain_size, source_rounds, checkpoint_size, block_elements,
        output.report);
    output.report.effective_block_elements = block_elements;
    output.report.source_rescan_rounds = source_rounds;

    const Digest selection = selection_identity(
        *source.matrix, *source.assignment, arrays,
        source.assignment_layout, source.half_size, claimed_value);
    ScratchRootCleanup cleanup(options.scratch_directory);
    try {
        ScratchTracker tracker(options.scratch_directory,
                               options.max_total_scratch_bytes,
                               options.min_free_bytes, cleanup,
                               output.report);

        output.sumcheck.proof.rounds.reserve(variables);
        output.sumcheck.point.reserve(variables);
        Fq2 running_claim = claimed_value;
        std::vector<Fq2> prefix_weights(prefix_count, Fq2::zero());
        prefix_weights.front() = Fq2::one();
        std::size_t active_prefixes = 1;
        for (std::size_t variable = 0; variable < source_rounds; ++variable) {
            const WiringSumcheckRound round = evaluate_source_round(
                source, arrays,
                std::span<const Fq2>(prefix_weights).first(active_prefixes),
                prefix_count, variable, domain_size, block_elements,
                retained_output_bytes, options, output.report);
            output.sumcheck.proof.rounds.push_back(round);
            observe_round(round, public_coin);
            const Fq2 challenge = public_coin.challenge_fq2();
            output.sumcheck.point.push_back(challenge);
            advance_claim(running_claim, challenge, round);
            expand_prefix_weights(prefix_weights, active_prefixes, challenge);
        }
        if (active_prefixes != prefix_count) {
            throw std::logic_error(
                "wiring prefix checkpoint is incomplete");
        }

        const Digest first_identity = checkpoint_identity(
            selection, checkpoint_size, output.sumcheck.point);
        ScratchArtifact current = materialize_checkpoint(
            source, arrays,
            std::span<const Fq2>(prefix_weights).first(active_prefixes),
            prefix_count, block_elements, first_identity,
            "checkpoint-" + std::to_string(source_rounds),
            retained_output_bytes, options, tracker, output.report);
        std::vector<Fq2>{}.swap(prefix_weights);

        for (std::size_t variable = source_rounds; variable < variables;
             ++variable) {
            const WiringSumcheckRound round = evaluate_checkpoint_round(
                current, block_elements, retained_output_bytes, options,
                output.report);
            output.sumcheck.proof.rounds.push_back(round);
            observe_round(round, public_coin);
            const Fq2 challenge = public_coin.challenge_fq2();
            output.sumcheck.point.push_back(challenge);
            advance_claim(running_claim, challenge, round);

            const std::size_t next_size = current.element_count / 2U;
            const Digest next_identity = checkpoint_identity(
                selection, next_size, output.sumcheck.point);
            ScratchArtifact next = fold_checkpoint(
                current, challenge, block_elements, next_identity,
                "fold-" + std::to_string(variable), retained_output_bytes,
                options, tracker, output.report);
            retire_scratch(current, tracker);
            current = std::move(next);
            ++output.report.fold_passes;
        }

        const std::array<Fq2, 2> terminal =
            read_terminal(current, output.report);
        output.sumcheck.matrix_evaluation = terminal[0];
        output.sumcheck.assignment_evaluation = terminal[1];
        output.sumcheck.final_claim = running_claim;
        if (running_claim != terminal[0] * terminal[1]) {
            throw std::logic_error(
                "artifact WiringCheck terminal mismatch");
        }
        retire_scratch(current, tracker);
        output.report.scratch_retained_physical_bytes =
            tracker.current_bytes();
        if (output.report.source_read_payload_bytes !=
                io.source_read_payload_bytes ||
            output.report.source_read_operations !=
                io.source_read_operations ||
            output.report.scratch_read_payload_bytes !=
                io.scratch_read_payload_bytes ||
            output.report.scratch_read_operations !=
                io.scratch_read_operations ||
            output.report.scratch_write_payload_bytes !=
                io.scratch_write_payload_bytes ||
            output.report.scratch_write_operations !=
                io.scratch_write_operations ||
            output.report.scratch_peak_physical_bytes != scratch.peak_bytes ||
            output.report.scratch_written_physical_bytes !=
                scratch.cumulative_bytes ||
            output.report.scratch_deleted_physical_bytes !=
                scratch.cumulative_bytes ||
            output.report.scratch_artifact_validation_bytes !=
                expected_scratch_validation_bytes ||
            output.report.scratch_retained_physical_bytes != 0 ||
            output.report.peak_working_field_bytes != exact_field_peak ||
            !std::filesystem::is_empty(options.scratch_directory)) {
            throw std::logic_error(
                "artifact WiringCheck accounting or cleanup mismatch");
        }
        cleanup.disarm();
        return output;
    } catch (...) {
        const std::exception_ptr failure = std::current_exception();
        cleanup.clear();
        std::rethrow_exception(failure);
    }
}

} // namespace laminate::spartan
