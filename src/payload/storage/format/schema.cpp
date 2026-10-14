/// @file schema.cpp
/// @brief Trace-store v4 constants, metadata codecs, and path rules.

#include "schema.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace laminate::payload {
namespace trace_store_format {

std::uint64_t checked_u64(std::size_t value, const char *what) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(what) +
                                      " does not fit in u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::size_t checked_size(std::uint64_t value, const char *what) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error(std::string(what) +
                                 " does not fit in size_t");
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *what) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(what) + " overflows u64");
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               const char *what) {
    if (left != 0 && right >
                         std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(what) + " overflows u64");
    }
    return left * right;
}

std::uint64_t manifest_encoded_bytes(std::size_t layer_count) {
    return checked_add(
        kManifestFixedBytes,
        checked_multiply(checked_u64(layer_count, "layer count"),
                         kLayerManifestBytes, "manifest layer bytes"),
        "manifest bytes");
}

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

void validate_dimensions(const LayerDimensions &dimensions) {
    if (dimensions.logical_size == 0 ||
        dimensions.logical_size > dimensions.padded_size ||
        !is_power_of_two(dimensions.padded_size) ||
        dimensions.payload_size > dimensions.logical_size ||
        dimensions.forward_size > dimensions.logical_size -
                                      dimensions.payload_size ||
        dimensions.payload_size + dimensions.forward_size !=
            dimensions.logical_size) {
        throw std::invalid_argument(
            "EncryptedTraceDescriptor: invalid layer dimensions");
    }
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & 0xffU));
    }
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

void append_magic(std::vector<std::uint8_t> &output,
                  const std::array<std::uint8_t, 8> &magic) {
    output.insert(output.end(), magic.begin(), magic.end());
}

ByteReader::ByteReader(std::span<const std::uint8_t> bytes)
    : bytes_(bytes) {}

std::uint64_t ByteReader::u64(const char *description) {
    require(sizeof(std::uint64_t), description);
    std::uint64_t result = 0;
    for (std::size_t byte = 0; byte < sizeof(std::uint64_t); ++byte) {
        result |= static_cast<std::uint64_t>(bytes_[position_ + byte])
                  << (8U * byte);
    }
    position_ += sizeof(std::uint64_t);
    return result;
}

Digest ByteReader::digest(const char *description) {
    require(Digest{}.size(), description);
    Digest result{};
    std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
                result.size(), result.begin());
    position_ += result.size();
    return result;
}

void ByteReader::magic(const std::array<std::uint8_t, 8> &expected,
                       const char *description) {
    require(expected.size(), description);
    if (!std::equal(expected.begin(), expected.end(),
                    bytes_.begin() +
                        static_cast<std::ptrdiff_t>(position_))) {
        throw std::runtime_error(std::string("invalid ") + description);
    }
    position_ += expected.size();
}

std::size_t ByteReader::position() const { return position_; }

void ByteReader::require(std::size_t count,
                         const char *description) const {
    if (count > bytes_.size() - position_) {
        throw std::runtime_error(std::string("truncated ") + description);
    }
}

std::uint64_t layout_code(TraceLayerLayout layout) {
    switch (layout) {
    case TraceLayerLayout::Wide:
        return 0;
    case TraceLayerLayout::BPeriodic:
        return 1;
    }
    throw std::invalid_argument("unknown encrypted trace layout");
}

TraceLayerLayout parse_layout(std::uint64_t code) {
    if (code == 0) {
        return TraceLayerLayout::Wide;
    }
    if (code == 1) {
        return TraceLayerLayout::BPeriodic;
    }
    throw std::runtime_error("trace store has an unknown layer layout");
}

std::uint64_t shape_code(PayloadKind kind) {
    switch (kind) {
    case PayloadKind::Laned:
        return 0;
    case PayloadKind::Wide:
        return 1;
    }
    throw std::invalid_argument("unknown payload shape kind");
}

PayloadKind parse_shape(std::uint64_t code) {
    if (code == 0) {
        return PayloadKind::Laned;
    }
    if (code == 1) {
        return PayloadKind::Wide;
    }
    throw std::runtime_error("trace store has an unknown payload shape");
}

std::uint64_t provenance_code(TraceProvenance provenance) {
    switch (provenance) {
    case TraceProvenance::SyntheticTrace:
        return 0;
    case TraceProvenance::FheEvaluated:
        return 1;
    }
    throw std::invalid_argument("unknown encrypted trace provenance");
}

TraceProvenance parse_provenance(std::uint64_t code) {
    if (code == 0) {
        return TraceProvenance::SyntheticTrace;
    }
    if (code == 1) {
        return TraceProvenance::FheEvaluated;
    }
    throw std::runtime_error("trace store has unknown trace provenance");
}

std::string indexed_filename(std::string_view prefix, std::uint64_t index,
                             std::string_view suffix) {
    std::array<char, 20> digits{};
    const auto [end, error] =
        std::to_chars(digits.data(), digits.data() + digits.size(), index);
    if (error != std::errc{}) {
        throw std::runtime_error("failed to encode trace-store file index");
    }
    const std::size_t digit_count =
        static_cast<std::size_t>(end - digits.data());
    if (digit_count > 16) {
        throw std::overflow_error("trace-store file index exceeds format width");
    }
    std::string name;
    name.reserve(prefix.size() + 16 + suffix.size());
    name.append(prefix);
    name.append(16 - digit_count, '0');
    name.append(digits.data(), digit_count);
    name.append(suffix);
    return name;
}

std::filesystem::path layer_path(const std::filesystem::path &directory,
                                 std::size_t layer_index,
                                 std::string_view suffix) {
    return directory /
           indexed_filename("layer-", checked_u64(layer_index, "layer index"),
                            suffix);
}

std::filesystem::path manifest_path(
    const std::filesystem::path &directory) {
    return directory / "manifest.bin";
}

std::filesystem::path partial_manifest_path(
    const std::filesystem::path &directory) {
    return directory / "manifest.partial";
}

std::filesystem::path retirement_session_path(
    const std::filesystem::path &directory) {
    return directory / "retirement-session.bin";
}

std::filesystem::path retirement_event_path(
    const std::filesystem::path &directory, std::uint64_t generation,
    std::string_view suffix) {
    return directory /
           indexed_filename("retirement-", generation, suffix);
}

} // namespace trace_store_format
} // namespace laminate::payload
