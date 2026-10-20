/// @file native_field_artifact.cpp
/// @brief Persistent framing and bounded I/O for native-field arrays.

#include "laminate/storage/native_field_artifact.hpp"

#include "laminate/field/serialization.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <locale>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

namespace laminate::storage {
namespace {

constexpr std::uint64_t kFormatVersion = 1;
constexpr std::size_t kMaximumArrays = 1ULL << 16U;
constexpr std::size_t kMaximumNameBytes = 128;
constexpr std::uint64_t kMaximumManifestBytes = 64ULL << 20U;
constexpr std::uint64_t kArrayHeaderFixedBytes =
    8 + sizeof(std::uint64_t) + Digest{}.size() +
    5 * sizeof(std::uint64_t);
constexpr std::uint64_t kManifestFixedBytes =
    8 + sizeof(std::uint64_t) + Digest{}.size() +
    2 * sizeof(std::uint64_t) + Digest{}.size();
constexpr std::uint64_t kManifestArrayFixedBytes =
    6 * sizeof(std::uint64_t) + Digest{}.size();

constexpr std::array<std::uint8_t, 8> kArrayMagic{
    'L', 'A', 'M', 'A', 'R', 'R', '0', '1'};
constexpr std::array<std::uint8_t, 8> kManifestMagic{
    'L', 'A', 'M', 'N', 'F', 'A', '0', '1'};

static_assert(
    std::is_nothrow_move_constructible_v<NativeFieldArtifactWriteResult>);

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
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(what) + " overflows u64");
    }
    return left * right;
}

bool is_zero(const Digest &digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

bool valid_name(std::string_view name) {
    if (name.empty() || name.size() > kMaximumNameBytes) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '-' ||
               character == '_' || character == '.';
    });
}

NativeFieldElementKind parse_kind(std::uint64_t code) {
    switch (code) {
    case static_cast<std::uint64_t>(NativeFieldElementKind::Fq):
        return NativeFieldElementKind::Fq;
    case static_cast<std::uint64_t>(NativeFieldElementKind::Fq2):
        return NativeFieldElementKind::Fq2;
    case static_cast<std::uint64_t>(
        NativeFieldElementKind::BaseFoldDigest):
        return NativeFieldElementKind::BaseFoldDigest;
    default:
        throw std::runtime_error("native-field artifact has unknown element kind");
    }
}

std::uint64_t array_encoded_bytes(std::string_view name,
                                  NativeFieldElementKind kind,
                                  std::uint64_t element_count) {
    const std::uint64_t payload = checked_multiply(
        element_count,
        checked_u64(encoded_element_bytes(kind), "element width"),
        "array payload bytes");
    return checked_add(
        checked_add(kArrayHeaderFixedBytes,
                    checked_u64(name.size(), "array name length"),
                    "array header bytes"),
        payload, "array file bytes");
}

std::uint64_t manifest_encoded_bytes(
    std::span<const NativeFieldArrayDescriptor> arrays,
    std::optional<std::string_view> additional_name = std::nullopt) {
    std::uint64_t result = kManifestFixedBytes;
    for (const NativeFieldArrayDescriptor &array : arrays) {
        result = checked_add(
            result,
            checked_add(kManifestArrayFixedBytes,
                        checked_u64(array.name.size(), "array name length"),
                        "manifest array bytes"),
            "manifest bytes");
    }
    if (additional_name) {
        result = checked_add(
            result,
            checked_add(kManifestArrayFixedBytes,
                        checked_u64(additional_name->size(),
                                    "array name length"),
                        "manifest array bytes"),
            "manifest bytes");
    }
    return result;
}

std::filesystem::path manifest_path(
    const std::filesystem::path &directory) {
    return directory / "manifest.bin";
}

std::filesystem::path partial_manifest_path(
    const std::filesystem::path &directory) {
    return directory / "manifest.partial";
}

std::filesystem::path array_path(const std::filesystem::path &directory,
                                 std::size_t index,
                                 std::string_view suffix) {
    std::ostringstream filename;
    filename.imbue(std::locale::classic());
    filename << "array-" << std::setw(16) << std::setfill('0') << index
             << suffix;
    return directory / filename.str();
}

std::uint64_t checked_file_size(const std::filesystem::path &path,
                                const char *what) {
    const std::uintmax_t size = std::filesystem::file_size(path);
    if (size > std::numeric_limits<std::uint64_t>::max() ||
        size > static_cast<std::uintmax_t>(
                   std::numeric_limits<std::streamoff>::max())) {
        throw std::runtime_error(std::string(what) +
                                 " exceeds the format size limit");
    }
    return static_cast<std::uint64_t>(size);
}

void write_exact(std::ostream &output, std::span<const std::uint8_t> bytes,
                 const char *what) {
    if (bytes.size() >
        static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::overflow_error(std::string(what) +
                                  " exceeds streamsize");
    }
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) {
        throw std::runtime_error(std::string("failed to write ") + what);
    }
}

void write_hashed(std::ostream &output, Sha256Hasher &hasher,
                  std::span<const std::uint8_t> bytes, const char *what) {
    write_exact(output, bytes, what);
    hasher.update(bytes);
}

std::array<std::uint8_t, 8> encode_u64(std::uint64_t value) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t byte = 0; byte < bytes.size(); ++byte) {
        bytes[byte] = static_cast<std::uint8_t>(value >> (8U * byte));
    }
    return bytes;
}

void write_u64_hashed(std::ostream &output, Sha256Hasher &hasher,
                      std::uint64_t value, const char *what) {
    const auto bytes = encode_u64(value);
    write_hashed(output, hasher, bytes, what);
}

void read_exact(std::istream &input, std::span<std::uint8_t> output,
                const char *what) {
    if (output.size() >
        static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error(std::string(what) +
                                 " exceeds streamsize");
    }
    input.read(reinterpret_cast<char *>(output.data()),
               static_cast<std::streamsize>(output.size()));
    if (!input) {
        throw std::runtime_error(std::string("truncated ") + what);
    }
}

void read_hashed(std::istream &input, Sha256Hasher &hasher,
                 std::span<std::uint8_t> output, const char *what) {
    read_exact(input, output, what);
    hasher.update(output);
}

std::uint64_t decode_u64(std::span<const std::uint8_t, 8> bytes) {
    std::uint64_t result = 0;
    for (std::size_t byte = 0; byte < bytes.size(); ++byte) {
        result |= static_cast<std::uint64_t>(bytes[byte]) << (8U * byte);
    }
    return result;
}

std::uint64_t read_u64(std::istream &input, const char *what) {
    std::array<std::uint8_t, 8> bytes{};
    read_exact(input, bytes, what);
    return decode_u64(bytes);
}

std::uint64_t read_u64_hashed(std::istream &input, Sha256Hasher &hasher,
                              const char *what) {
    std::array<std::uint8_t, 8> bytes{};
    read_hashed(input, hasher, bytes, what);
    return decode_u64(bytes);
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    const auto bytes = encode_u64(value);
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

std::vector<std::uint8_t> encode_manifest(
    const Digest &identity,
    std::span<const NativeFieldArrayDescriptor> arrays,
    std::uint64_t physical_bytes) {
    std::vector<std::uint8_t> output;
    output.reserve(checked_size(manifest_encoded_bytes(arrays),
                                "manifest length"));
    output.insert(output.end(), kManifestMagic.begin(), kManifestMagic.end());
    append_u64(output, kFormatVersion);
    append_digest(output, identity);
    append_u64(output, checked_u64(arrays.size(), "array count"));
    append_u64(output, physical_bytes);
    for (std::size_t index = 0; index < arrays.size(); ++index) {
        const NativeFieldArrayDescriptor &array = arrays[index];
        append_u64(output, checked_u64(index, "array index"));
        append_u64(output, static_cast<std::uint64_t>(array.kind));
        append_u64(output, array.element_count);
        append_u64(output, array.encoded_element_bytes);
        append_u64(output, array.physical_bytes);
        append_u64(output,
                   checked_u64(array.name.size(), "array name length"));
        output.insert(output.end(), array.name.begin(), array.name.end());
        append_digest(output, array.file_digest);
    }
    append_digest(output, sha256(output));
    return output;
}

class ByteReader {
  public:
    explicit ByteReader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

    void magic(std::span<const std::uint8_t> expected, const char *what) {
        require(expected.size(), what);
        if (!std::equal(expected.begin(), expected.end(),
                        bytes_.begin() +
                            static_cast<std::ptrdiff_t>(position_))) {
            throw std::runtime_error(std::string("invalid ") + what);
        }
        position_ += expected.size();
    }

    std::uint64_t u64(const char *what) {
        require(sizeof(std::uint64_t), what);
        const std::uint64_t result = decode_u64(
            std::span<const std::uint8_t, 8>(bytes_.data() + position_, 8));
        position_ += sizeof(std::uint64_t);
        return result;
    }

    Digest digest(const char *what) {
        require(Digest{}.size(), what);
        Digest result{};
        std::copy_n(bytes_.begin() +
                        static_cast<std::ptrdiff_t>(position_),
                    result.size(), result.begin());
        position_ += result.size();
        return result;
    }

    std::string string(std::size_t size, const char *what) {
        require(size, what);
        std::string result(
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
            bytes_.begin() +
                static_cast<std::ptrdiff_t>(position_ + size));
        position_ += size;
        return result;
    }

    std::size_t position() const { return position_; }

  private:
    void require(std::size_t count, const char *what) const {
        if (position_ > bytes_.size() ||
            count > bytes_.size() - position_) {
            throw std::runtime_error(std::string("truncated ") + what);
        }
    }

    std::span<const std::uint8_t> bytes_;
    std::size_t position_ = 0;
};

struct ParsedManifest {
    Digest identity{};
    std::vector<NativeFieldArrayDescriptor> arrays;
    std::uint64_t physical_bytes = 0;
};

ParsedManifest parse_manifest(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kManifestFixedBytes) {
        throw std::runtime_error("truncated native-field manifest");
    }
    const std::size_t body_size = bytes.size() - Digest{}.size();
    Digest recorded_digest{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(body_size),
                recorded_digest.size(), recorded_digest.begin());
    if (sha256(bytes.first(body_size)) != recorded_digest) {
        throw std::runtime_error("native-field manifest digest mismatch");
    }

    ByteReader reader(bytes.first(body_size));
    reader.magic(kManifestMagic, "native-field manifest magic");
    if (reader.u64("native-field manifest version") != kFormatVersion) {
        throw std::runtime_error("unsupported native-field artifact version");
    }
    ParsedManifest result;
    result.identity = reader.digest("native-field artifact identity");
    if (is_zero(result.identity)) {
        throw std::runtime_error("native-field manifest has zero identity");
    }
    const std::uint64_t array_count_word =
        reader.u64("native-field array count");
    if (array_count_word == 0 || array_count_word > kMaximumArrays) {
        throw std::runtime_error("invalid native-field array count");
    }
    result.physical_bytes = reader.u64("native-field physical bytes");
    const std::size_t array_count =
        checked_size(array_count_word, "array count");
    result.arrays.reserve(array_count);
    std::set<std::string> names;
    for (std::size_t index = 0; index < array_count; ++index) {
        if (reader.u64("native-field array index") != index) {
            throw std::runtime_error("noncanonical native-field array index");
        }
        NativeFieldArrayDescriptor descriptor;
        descriptor.kind = parse_kind(reader.u64("native-field element kind"));
        descriptor.element_count =
            reader.u64("native-field element count");
        descriptor.encoded_element_bytes =
            reader.u64("native-field element width");
        descriptor.physical_bytes =
            reader.u64("native-field array bytes");
        const std::uint64_t name_size_word =
            reader.u64("native-field array name length");
        if (name_size_word == 0 || name_size_word > kMaximumNameBytes) {
            throw std::runtime_error("invalid native-field array name length");
        }
        descriptor.name = reader.string(
            checked_size(name_size_word, "array name length"),
            "native-field array name");
        descriptor.file_digest =
            reader.digest("native-field array digest");
        if (!valid_name(descriptor.name) || descriptor.element_count == 0 ||
            descriptor.encoded_element_bytes !=
                encoded_element_bytes(descriptor.kind) ||
            descriptor.physical_bytes !=
                array_encoded_bytes(descriptor.name, descriptor.kind,
                                    descriptor.element_count) ||
            !names.insert(descriptor.name).second) {
            throw std::runtime_error("invalid native-field array descriptor");
        }
        result.arrays.push_back(std::move(descriptor));
    }
    if (reader.position() != body_size) {
        throw std::runtime_error("trailing data in native-field manifest");
    }
    return result;
}

std::vector<std::uint8_t> read_manifest_file(
    const std::filesystem::path &path) {
    if (!std::filesystem::is_regular_file(
            std::filesystem::symlink_status(path))) {
        throw std::runtime_error("native-field manifest is not a regular file");
    }
    const std::uint64_t length =
        checked_file_size(path, "native-field manifest");
    if (length > kMaximumManifestBytes) {
        throw std::runtime_error("native-field manifest exceeds v1 limit");
    }
    std::vector<std::uint8_t> result(
        checked_size(length, "manifest length"));
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open native-field manifest");
    }
    read_exact(input, result, "native-field manifest");
    return result;
}

void validate_array_payload(std::span<const std::uint8_t> bytes,
                            NativeFieldElementKind kind) {
    const std::size_t width = encoded_element_bytes(kind);
    for (std::size_t offset = 0; offset < bytes.size(); offset += width) {
        const auto element = bytes.subspan(offset, width);
        switch (kind) {
        case NativeFieldElementKind::Fq:
            (void)deserialize_fq(element);
            break;
        case NativeFieldElementKind::Fq2:
            (void)deserialize_fq2(element);
            break;
        case NativeFieldElementKind::BaseFoldDigest:
            break;
        }
    }
}

void validate_array_file(const std::filesystem::path &path,
                         std::size_t index,
                         const NativeFieldArrayDescriptor &descriptor,
                         const Digest &identity) {
    if (!std::filesystem::is_regular_file(
            std::filesystem::symlink_status(path)) ||
        checked_file_size(path, "native-field array") !=
            descriptor.physical_bytes) {
        throw std::runtime_error("native-field array boundary mismatch");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open native-field array");
    }
    Sha256Hasher hasher;
    std::array<std::uint8_t, 8> magic{};
    read_hashed(input, hasher, magic, "native-field array magic");
    if (magic != kArrayMagic ||
        read_u64_hashed(input, hasher, "native-field array version") !=
            kFormatVersion) {
        throw std::runtime_error("invalid native-field array header");
    }
    Digest recorded_identity{};
    read_hashed(input, hasher, recorded_identity,
                "native-field array identity");
    if (recorded_identity != identity ||
        read_u64_hashed(input, hasher, "native-field array index") != index ||
        parse_kind(read_u64_hashed(input, hasher,
                                   "native-field array kind")) !=
            descriptor.kind ||
        read_u64_hashed(input, hasher,
                        "native-field element count") !=
            descriptor.element_count ||
        read_u64_hashed(input, hasher,
                        "native-field element width") !=
            descriptor.encoded_element_bytes) {
        throw std::runtime_error("native-field array metadata mismatch");
    }
    const std::uint64_t name_size =
        read_u64_hashed(input, hasher, "native-field array name length");
    if (name_size != descriptor.name.size()) {
        throw std::runtime_error("native-field array name mismatch");
    }
    std::vector<std::uint8_t> name(descriptor.name.size());
    read_hashed(input, hasher, name, "native-field array name");
    if (!std::equal(name.begin(), name.end(), descriptor.name.begin())) {
        throw std::runtime_error("native-field array name mismatch");
    }

    constexpr std::size_t kBufferBytes = 64ULL << 10U;
    std::array<std::uint8_t, kBufferBytes> buffer{};
    const std::size_t width =
        checked_size(descriptor.encoded_element_bytes, "element width");
    std::uint64_t remaining = descriptor.element_count;
    while (remaining != 0) {
        const std::size_t elements = static_cast<std::size_t>(std::min<
            std::uint64_t>(remaining, kBufferBytes / width));
        const std::size_t bytes = elements * width;
        auto chunk = std::span<std::uint8_t>(buffer).first(bytes);
        read_hashed(input, hasher, chunk, "native-field array payload");
        validate_array_payload(chunk, descriptor.kind);
        remaining -= elements;
    }
    if (hasher.finish() != descriptor.file_digest) {
        throw std::runtime_error("native-field array digest mismatch");
    }
}

void validate_destination(const std::filesystem::path &directory) {
    if (directory.empty() ||
        !std::filesystem::is_directory(
            std::filesystem::symlink_status(directory))) {
        throw std::invalid_argument(
            "NativeFieldArtifactWriter: destination is not a real directory");
    }
    if (std::filesystem::directory_iterator(directory) !=
        std::filesystem::directory_iterator()) {
        throw std::invalid_argument(
            "NativeFieldArtifactWriter: destination is not empty");
    }
}

Digest hash_complete_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to reopen positional array");
    }
    Sha256Hasher hasher;
    std::array<std::uint8_t, 64ULL << 10U> buffer{};
    while (input) {
        input.read(reinterpret_cast<char *>(buffer.data()),
                   static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0) {
            hasher.update(std::span<const std::uint8_t>(buffer).first(
                static_cast<std::size_t>(count)));
        }
    }
    if (!input.eof()) {
        throw std::runtime_error("failed to hash positional array");
    }
    return hasher.finish();
}

} // namespace

std::size_t encoded_element_bytes(NativeFieldElementKind kind) {
    switch (kind) {
    case NativeFieldElementKind::Fq:
        return kSerializedFqBytes;
    case NativeFieldElementKind::Fq2:
        return kSerializedFq2Bytes;
    case NativeFieldElementKind::BaseFoldDigest:
        return basefold::Digest{}.size();
    }
    throw std::invalid_argument("unknown native-field element kind");
}

std::uint64_t native_field_artifact_physical_bytes(
    std::span<const NativeFieldArrayLayout> arrays) {
    if (arrays.empty() || arrays.size() > kMaximumArrays) {
        throw std::invalid_argument(
            "invalid native-field artifact array count");
    }
    std::set<std::string> names;
    std::vector<NativeFieldArrayDescriptor> descriptors;
    descriptors.reserve(arrays.size());
    std::uint64_t physical_bytes = 0;
    for (const NativeFieldArrayLayout &array : arrays) {
        if (!valid_name(array.name) || array.element_count == 0 ||
            !names.insert(array.name).second) {
            throw std::invalid_argument(
                "invalid native-field artifact array layout");
        }
        const std::uint64_t array_bytes = array_encoded_bytes(
            array.name, array.kind, array.element_count);
        descriptors.push_back(NativeFieldArrayDescriptor{
            array.name,
            array.kind,
            array.element_count,
            checked_u64(encoded_element_bytes(array.kind),
                        "element width"),
            array_bytes,
            {},
        });
        physical_bytes = checked_add(physical_bytes, array_bytes,
                                     "artifact physical bytes");
    }
    const std::uint64_t manifest_bytes = manifest_encoded_bytes(descriptors);
    if (manifest_bytes > kMaximumManifestBytes) {
        throw std::invalid_argument(
            "native-field artifact manifest exceeds v1 limit");
    }
    return checked_add(physical_bytes, manifest_bytes,
                       "artifact physical bytes");
}

struct NativeFieldArtifactWriter::Impl {
    std::filesystem::path directory;
    NativeFieldArtifactOptions options;
    Digest identity{};
    std::vector<NativeFieldArrayDescriptor> arrays;
    std::uint64_t physical_bytes = 0;
    std::uint64_t positional_publication_read_bytes = 0;
    std::uint64_t positional_publication_read_operations = 0;
    bool active = false;
    bool active_positional = false;
    bool finished = false;
    bool failed = false;
    std::string active_name;
    NativeFieldElementKind active_kind = NativeFieldElementKind::Fq;
    std::uint64_t active_count = 0;
    std::uint64_t active_written = 0;
    std::uint64_t active_file_bytes = 0;
    std::uint64_t active_payload_offset = 0;
    std::map<std::uint64_t, std::uint64_t> active_covered_ranges;
    std::filesystem::path active_partial;
    std::filesystem::path active_final;
    std::ofstream active_stream;
    Sha256Hasher active_hasher;

    void require_reservation(std::uint64_t additional) const {
        if (checked_add(physical_bytes, additional,
                        "artifact reservation") > options.max_total_bytes) {
            throw std::runtime_error(
                "NativeFieldArtifactWriter: byte quota exceeded");
        }
        const std::uint64_t required_free = checked_add(
            additional, options.min_free_bytes, "free-space reservation");
        if (std::filesystem::space(directory).available < required_free) {
            throw std::runtime_error(
                "NativeFieldArtifactWriter: free-space reserve exceeded");
        }
    }

    void abandon_partial() noexcept {
        if (active_stream.is_open()) {
            active_stream.close();
        }
        if (!active_partial.empty()) {
            std::error_code ignored;
            std::filesystem::remove(active_partial, ignored);
        }
    }

    template <typename Value, typename Encode>
    void append_values(std::span<const Value> values,
                       NativeFieldElementKind expected_kind,
                       Encode encode) {
        if (!active || active_positional || failed ||
            active_kind != expected_kind ||
            values.size() > active_count - active_written) {
            throw std::logic_error(
                "NativeFieldArtifactWriter: invalid typed append");
        }
        constexpr std::size_t kBufferBytes = 64ULL << 10U;
        std::array<std::uint8_t, kBufferBytes> buffer{};
        const std::size_t width = encoded_element_bytes(active_kind);
        std::size_t consumed = 0;
        try {
            while (consumed < values.size()) {
                const std::size_t count = std::min(
                    values.size() - consumed, kBufferBytes / width);
                for (std::size_t index = 0; index < count; ++index) {
                    const auto encoded = encode(values[consumed + index]);
                    std::copy(encoded.begin(), encoded.end(),
                              buffer.begin() + static_cast<std::ptrdiff_t>(
                                                   index * width));
                }
                write_hashed(active_stream, active_hasher,
                             std::span<const std::uint8_t>(buffer).first(
                                 count * width),
                             "native-field array payload");
                consumed += count;
            }
            active_written = checked_add(
                active_written, checked_u64(values.size(), "append count"),
                "written element count");
        } catch (...) {
            abandon_partial();
            active = false;
            failed = true;
            throw;
        }
    }
};

NativeFieldArtifactWriter::NativeFieldArtifactWriter(
    std::filesystem::path directory, NativeFieldArtifactOptions options,
    Digest identity)
    : impl_(std::make_unique<Impl>()) {
    if (directory.empty()) {
        throw std::invalid_argument(
            "NativeFieldArtifactWriter: destination path is empty");
    }
    directory = std::filesystem::absolute(directory).lexically_normal();
    validate_destination(directory);
    if (options.max_total_bytes == 0 || options.min_free_bytes == 0 ||
        is_zero(identity)) {
        throw std::invalid_argument(
            "NativeFieldArtifactWriter: invalid limits or identity");
    }
    impl_->directory = std::move(directory);
    impl_->options = options;
    impl_->identity = identity;
    impl_->require_reservation(kManifestFixedBytes);
}

NativeFieldArtifactWriter::~NativeFieldArtifactWriter() {
    if (impl_) {
        impl_->abandon_partial();
    }
}

NativeFieldArtifactWriter::NativeFieldArtifactWriter(
    NativeFieldArtifactWriter &&) noexcept = default;
NativeFieldArtifactWriter &NativeFieldArtifactWriter::operator=(
    NativeFieldArtifactWriter &&other) noexcept {
    if (this != &other) {
        if (impl_) {
            impl_->abandon_partial();
        }
        impl_ = std::move(other.impl_);
    }
    return *this;
}

void NativeFieldArtifactWriter::begin_array(
    std::string name, NativeFieldElementKind kind,
    std::uint64_t element_count) {
    if (!impl_ || impl_->active || impl_->finished || impl_->failed ||
        impl_->arrays.size() >= kMaximumArrays) {
        throw std::logic_error(
            "NativeFieldArtifactWriter: invalid array start");
    }
    if (!valid_name(name) || element_count == 0 ||
        std::any_of(impl_->arrays.begin(), impl_->arrays.end(),
                    [&](const NativeFieldArrayDescriptor &array) {
                        return array.name == name;
                    })) {
        throw std::invalid_argument(
            "NativeFieldArtifactWriter: invalid or duplicate array name");
    }
    (void)encoded_element_bytes(kind);
    const std::uint64_t file_bytes =
        array_encoded_bytes(name, kind, element_count);
    const std::uint64_t future_manifest =
        manifest_encoded_bytes(impl_->arrays, name);
    if (future_manifest > kMaximumManifestBytes) {
        throw std::invalid_argument(
            "NativeFieldArtifactWriter: manifest exceeds v1 limit");
    }
    impl_->require_reservation(checked_add(
        file_bytes, future_manifest, "array and manifest reservation"));

    const std::size_t index = impl_->arrays.size();
    impl_->active_name = std::move(name);
    impl_->active_kind = kind;
    impl_->active_count = element_count;
    impl_->active_written = 0;
    impl_->active_positional = false;
    impl_->active_file_bytes = file_bytes;
    impl_->active_payload_offset =
        file_bytes - checked_multiply(
                         element_count,
                         checked_u64(encoded_element_bytes(kind),
                                     "element width"),
                         "array payload bytes");
    impl_->active_covered_ranges.clear();
    impl_->active_partial = array_path(impl_->directory, index, ".partial");
    impl_->active_final = array_path(impl_->directory, index, ".bin");
    impl_->active_hasher = Sha256Hasher();
    impl_->active_stream.open(impl_->active_partial,
                              std::ios::binary | std::ios::trunc);
    if (!impl_->active_stream) {
        impl_->abandon_partial();
        impl_->failed = true;
        throw std::runtime_error(
            "NativeFieldArtifactWriter: failed to create partial array");
    }
    impl_->active = true;
    try {
        write_hashed(impl_->active_stream, impl_->active_hasher, kArrayMagic,
                     "native-field array magic");
        write_u64_hashed(impl_->active_stream, impl_->active_hasher,
                         kFormatVersion, "native-field array version");
        write_hashed(impl_->active_stream, impl_->active_hasher,
                     impl_->identity, "native-field artifact identity");
        write_u64_hashed(impl_->active_stream, impl_->active_hasher,
                         checked_u64(index, "array index"),
                         "native-field array index");
        write_u64_hashed(impl_->active_stream, impl_->active_hasher,
                         static_cast<std::uint64_t>(kind),
                         "native-field array kind");
        write_u64_hashed(impl_->active_stream, impl_->active_hasher,
                         element_count, "native-field element count");
        write_u64_hashed(impl_->active_stream, impl_->active_hasher,
                         checked_u64(encoded_element_bytes(kind),
                                     "element width"),
                         "native-field element width");
        write_u64_hashed(impl_->active_stream, impl_->active_hasher,
                         checked_u64(impl_->active_name.size(),
                                     "array name length"),
                         "native-field array name length");
        write_hashed(impl_->active_stream, impl_->active_hasher,
                     std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(
                             impl_->active_name.data()),
                         impl_->active_name.size()),
                     "native-field array name");
    } catch (...) {
        impl_->abandon_partial();
        impl_->active = false;
        impl_->active_positional = false;
        impl_->active_covered_ranges.clear();
        impl_->failed = true;
        throw;
    }
}

void NativeFieldArtifactWriter::begin_positional_fq_array(
    std::string name, std::uint64_t element_count) {
    begin_array(std::move(name), NativeFieldElementKind::Fq,
                element_count);
    impl_->active_positional = true;
}

void NativeFieldArtifactWriter::append(std::span<const Fq> values) {
    if (!impl_) {
        throw std::logic_error("cannot append through a moved writer");
    }
    impl_->append_values(values, NativeFieldElementKind::Fq,
                         [](const Fq &value) { return serialize(value); });
}

void NativeFieldArtifactWriter::append(std::span<const Fq2> values) {
    if (!impl_) {
        throw std::logic_error("cannot append through a moved writer");
    }
    impl_->append_values(values, NativeFieldElementKind::Fq2,
                         [](const Fq2 &value) { return serialize(value); });
}

void NativeFieldArtifactWriter::append(
    std::span<const basefold::Digest> values) {
    if (!impl_) {
        throw std::logic_error("cannot append through a moved writer");
    }
    impl_->append_values(
        values, NativeFieldElementKind::BaseFoldDigest,
        [](const basefold::Digest &value) { return value; });
}

void NativeFieldArtifactWriter::write_fq_at(
    std::uint64_t element_index, std::span<const Fq> values) {
    if (!impl_ || !impl_->active || !impl_->active_positional ||
        impl_->failed || values.empty() ||
        element_index > impl_->active_count ||
        values.size() > impl_->active_count - element_index ||
        values.size() > impl_->active_count - impl_->active_written) {
        throw std::logic_error(
            "NativeFieldArtifactWriter: invalid positional Fq write");
    }
    const std::uint64_t range_begin = element_index;
    const std::uint64_t range_end = checked_add(
        range_begin, checked_u64(values.size(), "positional write count"),
        "positional write range");
    auto following = impl_->active_covered_ranges.lower_bound(range_begin);
    if ((following != impl_->active_covered_ranges.end() &&
         following->first < range_end) ||
        (following != impl_->active_covered_ranges.begin() &&
         std::prev(following)->second > range_begin)) {
        throw std::invalid_argument(
            "NativeFieldArtifactWriter: overlapping positional Fq write");
    }
    constexpr std::size_t kBufferBytes = 64ULL << 10U;
    std::array<std::uint8_t, kBufferBytes> buffer{};
    std::size_t consumed = 0;
    try {
        const std::uint64_t position = checked_add(
            impl_->active_payload_offset,
            checked_multiply(element_index, kSerializedFqBytes,
                             "positional payload offset"),
            "positional file offset");
        if (position > static_cast<std::uint64_t>(
                           std::numeric_limits<std::streamoff>::max())) {
            throw std::overflow_error(
                "positional Fq write exceeds streamoff");
        }
        impl_->active_stream.seekp(
            static_cast<std::streamoff>(position), std::ios::beg);
        if (!impl_->active_stream) {
            throw std::runtime_error(
                "failed to seek positional Fq array");
        }
        while (consumed < values.size()) {
            const std::size_t count = std::min(
                values.size() - consumed,
                kBufferBytes / kSerializedFqBytes);
            for (std::size_t index = 0; index < count; ++index) {
                const SerializedFq encoded =
                    serialize(values[consumed + index]);
                std::copy(encoded.begin(), encoded.end(),
                          buffer.begin() + static_cast<std::ptrdiff_t>(
                                               index * kSerializedFqBytes));
            }
            write_exact(
                impl_->active_stream,
                std::span<const std::uint8_t>(buffer).first(
                    count * kSerializedFqBytes),
                "positional Fq array payload");
            consumed += count;
        }
        impl_->active_written = checked_add(
            impl_->active_written,
            checked_u64(values.size(), "positional write count"),
            "written element count");
        following = impl_->active_covered_ranges.lower_bound(range_begin);
        std::uint64_t merged_begin = range_begin;
        std::uint64_t merged_end = range_end;
        if (following != impl_->active_covered_ranges.begin()) {
            auto previous = std::prev(following);
            if (previous->second == range_begin) {
                merged_begin = previous->first;
                impl_->active_covered_ranges.erase(previous);
            }
        }
        following = impl_->active_covered_ranges.lower_bound(range_begin);
        if (following != impl_->active_covered_ranges.end() &&
            following->first == range_end) {
            merged_end = following->second;
            impl_->active_covered_ranges.erase(following);
        }
        impl_->active_covered_ranges.emplace(merged_begin, merged_end);
    } catch (...) {
        impl_->abandon_partial();
        impl_->active = false;
        impl_->active_positional = false;
        impl_->active_covered_ranges.clear();
        impl_->failed = true;
        throw;
    }
}

void NativeFieldArtifactWriter::finish_array() {
    if (!impl_ || !impl_->active || impl_->failed ||
        impl_->active_written != impl_->active_count ||
        (impl_->active_positional &&
         (impl_->active_covered_ranges.size() != 1U ||
          impl_->active_covered_ranges.begin()->first != 0 ||
          impl_->active_covered_ranges.begin()->second !=
              impl_->active_count))) {
        throw std::logic_error(
            "NativeFieldArtifactWriter: incomplete array");
    }
    try {
        impl_->active_stream.flush();
        if (!impl_->active_stream) {
            throw std::runtime_error(
                "NativeFieldArtifactWriter: failed to flush array");
        }
        impl_->active_stream.close();
        if (impl_->active_stream.fail() ||
            checked_file_size(impl_->active_partial,
                              "partial native-field array") !=
                impl_->active_file_bytes) {
            throw std::runtime_error(
                "NativeFieldArtifactWriter: array boundary mismatch");
        }
        const Digest file_digest = impl_->active_positional
                                       ? hash_complete_file(
                                             impl_->active_partial)
                                       : impl_->active_hasher.finish();
        if (impl_->active_positional) {
            impl_->positional_publication_read_bytes = checked_add(
                impl_->positional_publication_read_bytes,
                impl_->active_file_bytes,
                "positional publication read bytes");
            impl_->positional_publication_read_operations = checked_add(
                impl_->positional_publication_read_operations,
                impl_->active_file_bytes / (64ULL << 10U) +
                    (impl_->active_file_bytes % (64ULL << 10U) != 0 ? 1U
                                                                    : 0U),
                "positional publication read operations");
        }
        std::filesystem::rename(impl_->active_partial, impl_->active_final);
        impl_->arrays.push_back(NativeFieldArrayDescriptor{
            impl_->active_name,
            impl_->active_kind,
            impl_->active_count,
            checked_u64(encoded_element_bytes(impl_->active_kind),
                        "element width"),
            impl_->active_file_bytes,
            file_digest,
        });
        impl_->physical_bytes = checked_add(
            impl_->physical_bytes, impl_->active_file_bytes,
            "artifact physical bytes");
        impl_->active_partial.clear();
        impl_->active_final.clear();
        impl_->active = false;
        impl_->active_positional = false;
        impl_->active_covered_ranges.clear();
    } catch (...) {
        impl_->abandon_partial();
        if (!impl_->active_final.empty()) {
            std::error_code ignored;
            std::filesystem::remove(impl_->active_final, ignored);
        }
        impl_->active = false;
        impl_->active_positional = false;
        impl_->active_covered_ranges.clear();
        impl_->failed = true;
        throw;
    }
}

NativeFieldArtifactWriteResult NativeFieldArtifactWriter::finish() {
    if (!impl_ || impl_->active || impl_->finished || impl_->failed ||
        impl_->arrays.empty()) {
        throw std::logic_error(
            "NativeFieldArtifactWriter: incomplete artifact");
    }
    std::vector<std::uint8_t> manifest =
        encode_manifest(impl_->identity, impl_->arrays, 0);
    const std::uint64_t total_bytes = checked_add(
        impl_->physical_bytes, checked_u64(manifest.size(), "manifest bytes"),
        "artifact physical bytes");
    manifest = encode_manifest(impl_->identity, impl_->arrays, total_bytes);
    impl_->require_reservation(
        checked_u64(manifest.size(), "manifest bytes"));
    NativeFieldArtifactWriteResult result{
        impl_->directory,
        impl_->identity,
        impl_->arrays,
        total_bytes,
        impl_->positional_publication_read_bytes,
        impl_->positional_publication_read_operations,
    };

    const std::filesystem::path partial =
        partial_manifest_path(impl_->directory);
    const std::filesystem::path final = manifest_path(impl_->directory);
    try {
        std::ofstream output(partial, std::ios::binary | std::ios::trunc);
        if (!output) {
            throw std::runtime_error(
                "NativeFieldArtifactWriter: failed to create manifest");
        }
        write_exact(output, manifest, "native-field manifest");
        output.flush();
        if (!output) {
            throw std::runtime_error(
                "NativeFieldArtifactWriter: failed to flush manifest");
        }
        output.close();
        if (output.fail()) {
            throw std::runtime_error(
                "NativeFieldArtifactWriter: failed to close manifest");
        }
        std::filesystem::rename(partial, final);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(partial, ignored);
        impl_->failed = true;
        throw;
    }
    impl_->physical_bytes = total_bytes;
    impl_->finished = true;
    return result;
}

struct NativeFieldArtifact::Impl {
    std::filesystem::path directory;
    Digest identity{};
    std::vector<NativeFieldArrayDescriptor> arrays;
    std::uint64_t physical_bytes = 0;
};

struct NativeFieldArrayReader::Impl {
    static constexpr std::size_t kReadBufferBytes = 64ULL << 10U;

    std::filesystem::path path;
    NativeFieldArrayDescriptor descriptor;
    std::ifstream input;
    std::uint64_t payload_offset = 0;
    std::uint64_t current = 0;
    std::vector<std::uint8_t> encoded_buffer;

    Impl(std::filesystem::path selected_path,
         NativeFieldArrayDescriptor selected_descriptor,
         std::size_t index, const Digest &identity)
        : path(std::move(selected_path)),
          descriptor(std::move(selected_descriptor)),
          input(path, std::ios::binary) {
        if (!input ||
            checked_file_size(path, "native-field array reader") !=
                descriptor.physical_bytes) {
            throw std::runtime_error("failed to open native-field array reader");
        }
        std::array<std::uint8_t, 8> magic{};
        read_exact(input, magic, "native-field array magic");
        Digest recorded_identity{};
        if (magic != kArrayMagic ||
            read_u64(input, "native-field array version") != kFormatVersion) {
            throw std::runtime_error("invalid native-field array reader header");
        }
        read_exact(input, recorded_identity, "native-field array identity");
        if (recorded_identity != identity ||
            read_u64(input, "native-field array index") != index ||
            parse_kind(read_u64(input, "native-field array kind")) !=
                descriptor.kind ||
            read_u64(input, "native-field element count") !=
                descriptor.element_count ||
            read_u64(input, "native-field element width") !=
                descriptor.encoded_element_bytes ||
            read_u64(input, "native-field array name length") !=
                descriptor.name.size()) {
            throw std::runtime_error("native-field array reader mismatch");
        }
        std::vector<std::uint8_t> name(descriptor.name.size());
        read_exact(input, name, "native-field array name");
        if (!std::equal(name.begin(), name.end(), descriptor.name.begin())) {
            throw std::runtime_error("native-field array reader name mismatch");
        }
        payload_offset = checked_add(
            kArrayHeaderFixedBytes,
            checked_u64(descriptor.name.size(), "array name length"),
            "array payload offset");
    }

    void seek(std::uint64_t element_index) {
        if (element_index > descriptor.element_count) {
            throw std::out_of_range("native-field array seek is out of range");
        }
        const std::uint64_t offset = checked_add(
            payload_offset,
            checked_multiply(element_index, descriptor.encoded_element_bytes,
                             "array seek offset"),
            "array seek position");
        input.clear();
        input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!input) {
            throw std::runtime_error("failed to seek native-field array");
        }
        current = element_index;
    }

    template <typename Value, typename Decode>
    std::size_t read_values(std::span<Value> output,
                            NativeFieldElementKind expected_kind,
                            Decode decode) {
        if (descriptor.kind != expected_kind) {
            throw std::logic_error("native-field array reader type mismatch");
        }
        const std::size_t count = checked_size(
            std::min<std::uint64_t>(
                checked_u64(output.size(), "read output length"),
                descriptor.element_count - current),
            "read count");
        const std::size_t width =
            checked_size(descriptor.encoded_element_bytes, "element width");
        if (count == 0) {
            return 0;
        }
        if (width == 0 || width > kReadBufferBytes) {
            throw std::logic_error(
                "native-field array element exceeds its read buffer");
        }
        const std::size_t desired_buffer_bytes =
            count > kReadBufferBytes / width
                ? kReadBufferBytes
                : count * width;
        if (encoded_buffer.size() < desired_buffer_bytes) {
            encoded_buffer.resize(desired_buffer_bytes);
        }
        const std::size_t buffer_elements = encoded_buffer.size() / width;
        std::size_t consumed = 0;
        while (consumed < count) {
            const std::size_t chunk =
                std::min(count - consumed, buffer_elements);
            const std::size_t encoded_bytes = chunk * width;
            auto bytes = std::span<std::uint8_t>(encoded_buffer)
                             .first(encoded_bytes);
            read_exact(input, bytes, "native-field array elements");
            for (std::size_t index = 0; index < chunk; ++index) {
                output[consumed + index] = decode(
                    std::span<const std::uint8_t>(encoded_buffer)
                        .subspan(index * width, width));
            }
            consumed += chunk;
        }
        current += count;
        return count;
    }
};

NativeFieldArtifact
NativeFieldArtifactWriter::trusted_finished_artifact() const {
    if (!impl_ || !impl_->finished || impl_->failed || impl_->active ||
        impl_->arrays.empty()) {
        throw std::logic_error(
            "NativeFieldArtifactWriter: artifact is not finished");
    }
    auto artifact = std::make_shared<NativeFieldArtifact::Impl>();
    artifact->directory = impl_->directory;
    artifact->identity = impl_->identity;
    artifact->arrays = impl_->arrays;
    artifact->physical_bytes = impl_->physical_bytes;
    return NativeFieldArtifact(std::move(artifact));
}

NativeFieldArrayReader::NativeFieldArrayReader(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
NativeFieldArrayReader::~NativeFieldArrayReader() = default;
NativeFieldArrayReader::NativeFieldArrayReader(
    NativeFieldArrayReader &&) noexcept = default;
NativeFieldArrayReader &NativeFieldArrayReader::operator=(
    NativeFieldArrayReader &&) noexcept = default;

NativeFieldElementKind NativeFieldArrayReader::kind() const {
    if (!impl_) {
        throw std::logic_error("cannot inspect a moved array reader");
    }
    return impl_->descriptor.kind;
}

std::uint64_t NativeFieldArrayReader::size() const {
    if (!impl_) {
        throw std::logic_error("cannot inspect a moved array reader");
    }
    return impl_->descriptor.element_count;
}

std::uint64_t NativeFieldArrayReader::position() const {
    if (!impl_) {
        throw std::logic_error("cannot inspect a moved array reader");
    }
    return impl_->current;
}

void NativeFieldArrayReader::seek(std::uint64_t element_index) {
    if (!impl_) {
        throw std::logic_error("cannot seek a moved array reader");
    }
    impl_->seek(element_index);
}

void NativeFieldArrayReader::rewind() { seek(0); }

std::size_t NativeFieldArrayReader::read(std::span<Fq> output) {
    if (!impl_) {
        throw std::logic_error("cannot read a moved array reader");
    }
    return impl_->read_values(
        output, NativeFieldElementKind::Fq,
        [](std::span<const std::uint8_t> bytes) {
            return deserialize_fq(bytes);
        });
}

std::size_t NativeFieldArrayReader::read(std::span<Fq2> output) {
    if (!impl_) {
        throw std::logic_error("cannot read a moved array reader");
    }
    return impl_->read_values(
        output, NativeFieldElementKind::Fq2,
        [](std::span<const std::uint8_t> bytes) {
            return deserialize_fq2(bytes);
        });
}

std::size_t NativeFieldArrayReader::read(
    std::span<basefold::Digest> output) {
    if (!impl_) {
        throw std::logic_error("cannot read a moved array reader");
    }
    return impl_->read_values(
        output, NativeFieldElementKind::BaseFoldDigest,
        [](std::span<const std::uint8_t> bytes) {
            basefold::Digest result{};
            std::copy(bytes.begin(), bytes.end(), result.begin());
            return result;
        });
}

NativeFieldArtifact::NativeFieldArtifact(std::shared_ptr<const Impl> impl)
    : impl_(std::move(impl)) {}

NativeFieldArtifact NativeFieldArtifact::open(
    const std::filesystem::path &selected_directory,
    const Digest &expected_identity) {
    if (selected_directory.empty()) {
        throw std::invalid_argument(
            "NativeFieldArtifact: directory path is empty");
    }
    const std::filesystem::path directory =
        std::filesystem::absolute(selected_directory).lexically_normal();
    if (directory.empty() || is_zero(expected_identity) ||
        !std::filesystem::is_directory(
            std::filesystem::symlink_status(directory))) {
        throw std::invalid_argument(
            "NativeFieldArtifact: invalid directory or expected identity");
    }
    const std::vector<std::uint8_t> manifest_bytes =
        read_manifest_file(manifest_path(directory));
    ParsedManifest manifest = parse_manifest(manifest_bytes);
    if (manifest.identity != expected_identity) {
        throw std::runtime_error("native-field artifact identity mismatch");
    }

    std::set<std::filesystem::path> expected_files;
    expected_files.insert(manifest_path(directory).filename());
    std::uint64_t physical_bytes =
        checked_u64(manifest_bytes.size(), "manifest bytes");
    for (std::size_t index = 0; index < manifest.arrays.size(); ++index) {
        const std::filesystem::path path =
            array_path(directory, index, ".bin");
        expected_files.insert(path.filename());
        validate_array_file(path, index, manifest.arrays[index],
                            manifest.identity);
        physical_bytes = checked_add(
            physical_bytes, manifest.arrays[index].physical_bytes,
            "artifact physical bytes");
    }
    if (physical_bytes != manifest.physical_bytes) {
        throw std::runtime_error("native-field artifact byte report mismatch");
    }
    std::size_t actual_files = 0;
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory)) {
        if (!std::filesystem::is_regular_file(entry.symlink_status()) ||
            !expected_files.contains(entry.path().filename())) {
            throw std::runtime_error(
                "native-field artifact contains unexpected data");
        }
        ++actual_files;
    }
    if (actual_files != expected_files.size()) {
        throw std::runtime_error("native-field artifact is incomplete");
    }

    auto impl = std::make_shared<Impl>();
    impl->directory = directory;
    impl->identity = manifest.identity;
    impl->arrays = std::move(manifest.arrays);
    impl->physical_bytes = manifest.physical_bytes;
    return NativeFieldArtifact(std::move(impl));
}

const std::filesystem::path &NativeFieldArtifact::directory() const {
    return impl_->directory;
}

const Digest &NativeFieldArtifact::identity() const {
    return impl_->identity;
}

const std::vector<NativeFieldArrayDescriptor> &
NativeFieldArtifact::arrays() const {
    return impl_->arrays;
}

std::uint64_t NativeFieldArtifact::physical_bytes() const {
    return impl_->physical_bytes;
}

const NativeFieldArrayDescriptor &
NativeFieldArtifact::array(std::string_view name) const {
    const auto found = std::find_if(
        impl_->arrays.begin(), impl_->arrays.end(),
        [&](const NativeFieldArrayDescriptor &descriptor) {
            return descriptor.name == name;
        });
    if (found == impl_->arrays.end()) {
        throw std::out_of_range("unknown native-field array name");
    }
    return *found;
}

NativeFieldArrayReader
NativeFieldArtifact::open_array(std::string_view name) const {
    const NativeFieldArrayDescriptor &descriptor = array(name);
    const std::size_t index = static_cast<std::size_t>(
        &descriptor - impl_->arrays.data());
    return NativeFieldArrayReader(std::make_unique<NativeFieldArrayReader::Impl>(
        array_path(impl_->directory, index, ".bin"), descriptor, index,
        impl_->identity));
}

} // namespace laminate::storage
