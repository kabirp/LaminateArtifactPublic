/// @file layer_validation.cpp
/// @brief Full validation and indexing of one immutable layer file.

#include "manifest.hpp"

#include "laminate/transcript/hash.hpp"

#include <array>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace laminate::payload {
namespace trace_store_format {

std::vector<std::uint8_t> read_small_file(
    const std::filesystem::path &path, std::uint64_t maximum_bytes,
    const char *description, FileIdentity *selected_identity) {
    const std::shared_ptr<BoundInputFile> input =
        open_bound_input_file(path, description);
    const std::uint64_t size = input->size();
    if (size > maximum_bytes ||
        size > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error(std::string(description) +
                                 " is unreasonably large");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    read_exact(*input, bytes, description);
    input->require_unchanged(description);
    if (selected_identity != nullptr) {
        *selected_identity = input->identity();
    }
    return bytes;
}

std::shared_ptr<const LayerFileInfo> scan_layer_file(
    const std::filesystem::path &path, std::size_t layer_index,
    const EncryptedTraceLayerDescriptor &descriptor,
    const LayerFileSummary &summary, std::uint64_t &logical_bytes,
    std::uint64_t maximum_record_bytes,
    const std::function<void(
        std::size_t, std::size_t,
        std::span<const std::uint8_t>)> &validate_record) {
    const std::shared_ptr<BoundInputFile> input =
        open_bound_input_file(path, "trace layer file");
    const FileIdentity initial_identity = input->identity();
    const std::uint64_t actual_size = input->size();
    if (actual_size != summary.file_size || actual_size < kLayerHeaderBytes) {
        throw std::runtime_error("truncated or oversized trace layer file");
    }

    std::array<std::uint8_t, 8> magic{};
    read_exact(*input, magic, "trace layer header");
    if (magic != kLayerMagic ||
        read_u64(*input, "trace layer version") != kFormatVersion ||
        read_u64(*input, "trace layer index") !=
            checked_u64(layer_index, "layer index") ||
        read_u64(*input, "trace layer record count") !=
            checked_u64(descriptor.record_count,
                        "record count")) {
        throw std::runtime_error("invalid trace layer header");
    }
    const std::uint64_t index_offset =
        read_u64(*input, "trace layer index offset");
    if (index_offset < kLayerHeaderBytes || index_offset >= actual_size) {
        throw std::runtime_error("invalid trace layer index offset");
    }
    const std::uint64_t indexed_offsets = checked_multiply(
        checked_u64(descriptor.record_count, "record count"),
        sizeof(std::uint64_t), "trace layer index bytes");
    const std::uint64_t expected_index_bytes = checked_add(
        kIndexHeaderBytes, indexed_offsets, "trace layer index bytes");
    if (expected_index_bytes != actual_size - index_offset) {
        throw std::runtime_error("invalid trace layer index length");
    }
    const std::uint64_t minimum_record_bytes = checked_multiply(
        checked_u64(descriptor.record_count, "record count"),
        sizeof(std::uint64_t) + 1, "minimum trace layer records");
    if (minimum_record_bytes > index_offset - kLayerHeaderBytes) {
        throw std::runtime_error(
            "trace layer cannot contain its advertised records");
    }

    auto info = std::make_shared<LayerFileInfo>();
    info->path = path;
    info->file_size = actual_size;
    info->index_offset = index_offset;
    info->maximum_record_bytes = maximum_record_bytes;
    auto offsets = std::make_shared<std::vector<std::uint64_t>>();
    offsets->reserve(descriptor.record_count);
    Digest layer_digest = initial_layer_digest(
        layer_index, descriptor.record_count);
    for (std::size_t record = 0; record < descriptor.record_count;
         ++record) {
        const std::uint64_t offset =
            stream_position(*input, "trace layer record offset");
        if (offset >= index_offset) {
            throw std::runtime_error("truncated trace layer records");
        }
        offsets->push_back(offset);
        const std::uint64_t length =
            read_u64(*input, "trace layer record length");
        const std::uint64_t payload_offset =
            stream_position(*input, "trace layer payload offset");
        if (length == 0 || length > kMaximumRecordBytes ||
            length > maximum_record_bytes ||
            payload_offset > index_offset ||
            length > index_offset - payload_offset) {
            throw std::runtime_error("invalid trace layer record length");
        }
        std::vector<std::uint8_t> encoded_record(
            checked_size(length, "record length"));
        read_exact(*input, encoded_record, "trace layer record");
        validate_record(layer_index, record, encoded_record);
        const Digest record_digest = sha256(encoded_record);
        layer_digest = extend_layer_digest(
            layer_digest, record, encoded_record.size(), record_digest);
        logical_bytes = checked_add(logical_bytes, length,
                                    "logical record bytes");
    }
    if (stream_position(*input, "trace layer records") != index_offset) {
        throw std::runtime_error("trace layer record/index boundary mismatch");
    }

    read_exact(*input, magic, "trace layer index magic");
    if (magic != kIndexMagic ||
        read_u64(*input, "trace layer index version") != kFormatVersion ||
        read_u64(*input, "trace layer indexed count") !=
            checked_u64(descriptor.record_count,
                        "record count")) {
        throw std::runtime_error("invalid trace layer index");
    }
    for (std::uint64_t expected : *offsets) {
        if (read_u64(*input, "trace layer record index") != expected) {
            throw std::runtime_error("corrupt trace layer record index");
        }
    }
    if (stream_position(*input, "trace layer end") != actual_size) {
        throw std::runtime_error("trace layer has trailing data");
    }
    if (layer_digest != summary.digest) {
        throw std::runtime_error("corrupt trace layer record digest");
    }
    input->require_unchanged("trace layer file");
    info->offsets = std::move(offsets);
    info->identity = initial_identity;
    return info;
}

} // namespace trace_store_format
} // namespace laminate::payload
