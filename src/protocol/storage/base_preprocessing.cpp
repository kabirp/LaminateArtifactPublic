/// @file base_preprocessing.cpp
/// @brief Streaming validation and manifest-last Base preprocessing storage.

#include "laminate/protocol/storage/base_preprocessing.hpp"

#include "laminate/payload/setup/encoding.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fstream>
#include <limits>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

namespace laminate::protocol {
namespace {

constexpr std::array<std::uint8_t, 8> kManifestMagic{
    'L', 'M', 'B', 'P', 'R', 'E', '0', '1'};
constexpr std::array<std::uint8_t, 8> kEvaluationBundleMagic{
    'L', 'M', 'S', 'E', 'A', 'L', 'E', 'V'};
constexpr std::array<std::uint8_t, 8> kClientBundleMagic{
    'L', 'M', 'S', 'E', 'A', 'L', 'C', 'L'};
constexpr std::uint8_t kSealBundleVersion = 1;
constexpr std::size_t kMaximumFilenameBytes = 128;
constexpr std::string_view kManifestIdentityDomain =
    "LaminateImpl/BasePreprocessingManifestIdentity/v1";
constexpr std::string_view kManifestChecksumDomain =
    "LaminateImpl/BasePreprocessingManifestChecksum/v1";
constexpr std::string_view kSealBundleChecksumDomain =
    "LaminateImpl/SealContextBundleChecksum/v1";

enum class BundleRole { Evaluation, Client };

std::uint64_t checked_u64(std::size_t value, const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " does not fit u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::size_t checked_size(std::uint64_t value, const char *description) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error(std::string(description) +
                                 " does not fit size_t");
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left + right;
}

bool is_zero(const Digest &value) {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

std::span<const std::uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t *>(value.data()),
            value.size()};
}

Digest domain_hash(std::string_view domain,
                   std::span<const std::uint8_t> value) {
    Sha256Hasher hasher;
    hasher.update(bytes(domain));
    hasher.update(value);
    return hasher.finish();
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &value) {
    output.insert(output.end(), value.begin(), value.end());
}

void append_string(std::vector<std::uint8_t> &output,
                   std::string_view value) {
    append_u64(output, checked_u64(value.size(), "manifest string size"));
    output.insert(output.end(), value.begin(), value.end());
}

bool valid_filename(std::string_view name) {
    if (name.empty() || name == "." || name == ".." ||
        name.size() > kMaximumFilenameBytes) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') ||
               character == '-' || character == '_' || character == '.';
    });
}

void validate_cache_metadata(
    const std::optional<BasePreparedPlaintextCacheMetadata> &metadata) {
    if (!metadata) {
        return;
    }
    if ((metadata->logical_plaintexts == 0) !=
            (metadata->level_representations == 0) ||
        (metadata->level_representations == 0) !=
            (metadata->ntt_coefficient_bytes == 0) ||
        metadata->level_representations < metadata->logical_plaintexts) {
        throw std::invalid_argument(
            "Base prepared-cache metadata is internally inconsistent");
    }
}

std::filesystem::path normalize_directory(
    const std::filesystem::path &directory) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(
            "Base preprocessing directory must be a caller-owned regular "
            "directory");
    }
    return std::filesystem::canonical(directory);
}

std::filesystem::path normalize_direct_child(
    const std::filesystem::path &directory,
    const std::filesystem::path &selected, const char *description) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(selected);
    if (!std::filesystem::is_regular_file(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(std::string(description) +
                                    " must be a regular file");
    }
    const std::filesystem::path canonical =
        std::filesystem::canonical(selected);
    const std::string filename = canonical.filename().string();
    if (canonical.parent_path() != directory || !valid_filename(filename)) {
        throw std::invalid_argument(std::string(description) +
                                    " must be a named direct child of the "
                                    "preprocessing directory");
    }
    return canonical;
}

std::filesystem::path normalize_role_bundle(
    const std::filesystem::path &selected, const char *description) {
    const std::filesystem::path absolute =
        std::filesystem::absolute(selected);
    const std::filesystem::path role_directory =
        normalize_directory(absolute.parent_path());
    return normalize_direct_child(role_directory, absolute, description);
}

std::set<std::string> directory_entries(
    const std::filesystem::path &directory) {
    std::set<std::string> result;
    for (const std::filesystem::directory_entry &entry :
         std::filesystem::directory_iterator(directory)) {
        const std::string name = entry.path().filename().string();
        if (!valid_filename(name) || !result.insert(name).second) {
            throw std::runtime_error(
                "Base preprocessing directory has a noncanonical entry");
        }
    }
    return result;
}

void require_directory_entries(
    const std::filesystem::path &directory,
    std::initializer_list<std::string> expected) {
    if (directory_entries(directory) != std::set<std::string>(expected)) {
        throw std::invalid_argument(
            "Base preprocessing directory contains unowned files");
    }
}

class StreamingBundleReader {
  public:
    StreamingBundleReader(const std::filesystem::path &path,
                          std::uint64_t max_bytes)
        : path_(path), expected_bytes_(file_size(path, max_bytes)),
          modified_(std::filesystem::last_write_time(path)),
          input_(path, std::ios::binary) {
        if (!input_) {
            throw std::runtime_error(
                "failed to open Base preprocessing bundle");
        }
        bundle_checksum_.update(bytes(kSealBundleChecksumDomain));
    }

    std::array<std::uint8_t, 10> header() {
        std::array<std::uint8_t, 10> result{};
        read(result, true, "SEAL bundle header");
        return result;
    }

    std::uint64_t u64(const char *description) {
        std::array<std::uint8_t, 8> encoded{};
        read(encoded, true, description);
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < encoded.size(); ++byte) {
            result |= static_cast<std::uint64_t>(encoded[byte]) <<
                      (8U * byte);
        }
        return result;
    }

    Digest digest(const char *description, bool in_bundle_checksum = true) {
        Digest result{};
        read(result, in_bundle_checksum, description);
        return result;
    }

    void blob(const char *description) {
        const std::uint64_t count = u64(description);
        consume(count, description);
    }

    BasePreprocessingBundleFile finish(std::string filename,
                                       const Digest &identity) {
        if (consumed_ > expected_bytes_ ||
            expected_bytes_ - consumed_ != Digest{}.size()) {
            throw std::runtime_error(
                "SEAL bundle has trailing or missing framed data");
        }
        const Digest encoded_checksum =
            digest("SEAL bundle checksum", false);
        if (bundle_checksum_.finish() != encoded_checksum ||
            input_.peek() != std::ifstream::traits_type::eof()) {
            throw std::runtime_error("SEAL bundle checksum mismatch");
        }
        if (!std::filesystem::is_regular_file(
                std::filesystem::symlink_status(path_)) ||
            std::filesystem::is_symlink(
                std::filesystem::symlink_status(path_)) ||
            std::filesystem::file_size(path_) != expected_bytes_ ||
            std::filesystem::last_write_time(path_) != modified_) {
            throw std::runtime_error(
                "SEAL bundle changed during validation");
        }
        return BasePreprocessingBundleFile{
            std::move(filename), expected_bytes_, file_digest_.finish(),
            identity};
    }

  private:
    static std::uint64_t file_size(const std::filesystem::path &path,
                                   std::uint64_t max_bytes) {
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(path);
        if (!std::filesystem::is_regular_file(status) ||
            std::filesystem::is_symlink(status)) {
            throw std::invalid_argument(
                "Base preprocessing bundle is not a regular file");
        }
        const std::uintmax_t size = std::filesystem::file_size(path);
        if (max_bytes == 0 || size > max_bytes ||
            size > std::numeric_limits<std::uint64_t>::max() ||
            size > static_cast<std::uintmax_t>(
                       std::numeric_limits<std::streamoff>::max())) {
            throw std::invalid_argument(
                "Base preprocessing bundle exceeds its open limit");
        }
        return static_cast<std::uint64_t>(size);
    }

    template <std::size_t Size>
    void read(std::array<std::uint8_t, Size> &output,
              bool in_bundle_checksum, const char *description) {
        read(std::span<std::uint8_t>(output), in_bundle_checksum,
             description);
    }

    void read(std::span<std::uint8_t> output, bool in_bundle_checksum,
              const char *description) {
        if (output.size() > static_cast<std::size_t>(
                                std::numeric_limits<std::streamsize>::max()) ||
            checked_u64(output.size(), description) >
                expected_bytes_ - std::min(consumed_, expected_bytes_)) {
            throw std::runtime_error(std::string("truncated ") +
                                     description);
        }
        input_.read(reinterpret_cast<char *>(output.data()),
                    static_cast<std::streamsize>(output.size()));
        if (!input_) {
            throw std::runtime_error(std::string("truncated ") +
                                     description);
        }
        consumed_ = checked_add(consumed_, checked_u64(output.size(),
                                                       description),
                                "SEAL bundle bytes");
        file_digest_.update(output);
        if (in_bundle_checksum) {
            bundle_checksum_.update(output);
        }
    }

    void consume(std::uint64_t count, const char *description) {
        if (count > expected_bytes_ - std::min(consumed_, expected_bytes_)) {
            throw std::runtime_error(std::string("truncated ") +
                                     description);
        }
        std::array<std::uint8_t, 64ULL << 10U> buffer{};
        while (count != 0) {
            const std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uint64_t>(count, buffer.size()));
            read(std::span<std::uint8_t>(buffer).first(chunk), true,
                 description);
            count -= chunk;
        }
    }

    std::filesystem::path path_;
    std::uint64_t expected_bytes_ = 0;
    std::filesystem::file_time_type modified_;
    std::ifstream input_;
    std::uint64_t consumed_ = 0;
    Sha256Hasher file_digest_;
    Sha256Hasher bundle_checksum_;
};

BasePreprocessingBundleFile inspect_bundle(
    const std::filesystem::path &path, std::uint64_t max_bytes,
    BundleRole role) {
    StreamingBundleReader reader(path, max_bytes);
    const auto header = reader.header();
    const auto &magic = role == BundleRole::Evaluation
                            ? kEvaluationBundleMagic
                            : kClientBundleMagic;
    if (!std::equal(magic.begin(), magic.end(), header.begin()) ||
        header[8] != kSealBundleVersion || header[9] != 0) {
        throw std::runtime_error(
            "Base preprocessing bundle has the wrong role or version");
    }
    reader.blob("SEAL parameter descriptor");
    const Digest identity = reader.digest("SEAL bundle identity");
    if (is_zero(identity)) {
        throw std::runtime_error("SEAL bundle identity is zero");
    }
    reader.blob("SEAL public key");
    if (role == BundleRole::Evaluation) {
        reader.blob("SEAL relinearization keys");
        reader.blob("SEAL Galois keys");
    } else {
        reader.blob("SEAL secret key");
    }
    return reader.finish(path.filename().string(), identity);
}

void append_bundle_file(std::vector<std::uint8_t> &body,
                        const BasePreprocessingBundleFile &file) {
    append_string(body, file.filename);
    append_u64(body, file.serialized_bytes);
    append_digest(body, file.file_digest);
    append_digest(body, file.bundle_identity);
}

std::vector<std::uint8_t> manifest_body(
    const BasePreprocessingManifest &manifest) {
    std::vector<std::uint8_t> body;
    append_digest(body, manifest.public_setup_digest);
    append_digest(body, manifest.payload_digest);
    append_digest(body, manifest.layered_digest);
    append_digest(body, manifest.circuit_digest);
    append_digest(body, manifest.bundle_identity);
    append_u64(body, checked_u64(manifest.public_setup_canonical.size(),
                                 "canonical PublicSetup bytes"));
    body.insert(body.end(), manifest.public_setup_canonical.begin(),
                manifest.public_setup_canonical.end());
    append_bundle_file(body, manifest.evaluation_bundle);
    append_bundle_file(body, manifest.client_bundle);
    if (manifest.prepared_plaintext_cache) {
        append_u64(body,
                   manifest.prepared_plaintext_cache->logical_plaintexts);
        append_u64(body,
                   manifest.prepared_plaintext_cache->level_representations);
        append_u64(body,
                   manifest.prepared_plaintext_cache->ntt_coefficient_bytes);
    }
    return body;
}

std::vector<std::uint8_t> encode_manifest(
    BasePreprocessingManifest &manifest) {
    validate_cache_metadata(manifest.prepared_plaintext_cache);
    const std::vector<std::uint8_t> body = manifest_body(manifest);
    manifest.identity = domain_hash(kManifestIdentityDomain, body);
    std::vector<std::uint8_t> output;
    output.insert(output.end(), kManifestMagic.begin(), kManifestMagic.end());
    append_u64(output, kBasePreprocessingManifestVersion);
    append_u64(output, manifest.prepared_plaintext_cache ? 1U : 0U);
    append_digest(output, manifest.identity);
    append_u64(output, checked_u64(body.size(), "preprocessing body size"));
    output.insert(output.end(), body.begin(), body.end());
    append_digest(output, domain_hash(kManifestChecksumDomain, output));
    manifest.manifest_bytes =
        checked_u64(output.size(), "preprocessing manifest size");
    return output;
}

class ByteReader {
  public:
    explicit ByteReader(std::span<const std::uint8_t> bytes)
        : bytes_(bytes) {}

    std::uint64_t u64(const char *description) {
        require(sizeof(std::uint64_t), description);
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < sizeof(result); ++byte) {
            result |= static_cast<std::uint64_t>(bytes_[position_ + byte]) <<
                      (8U * byte);
        }
        position_ += sizeof(result);
        return result;
    }

    Digest digest(const char *description) {
        require(Digest{}.size(), description);
        Digest result{};
        std::copy_n(bytes_.begin() +
                        static_cast<std::ptrdiff_t>(position_),
                    result.size(), result.begin());
        position_ += result.size();
        return result;
    }

    std::string string(const char *description) {
        const std::uint64_t size = u64(description);
        if (size == 0 || size > kMaximumFilenameBytes) {
            throw std::runtime_error("invalid preprocessing filename size");
        }
        require(checked_size(size, description), description);
        std::string result(
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_ + size));
        position_ += checked_size(size, description);
        return result;
    }

    std::vector<std::uint8_t> byte_vector(const char *description) {
        const std::uint64_t size = u64(description);
        require(checked_size(size, description), description);
        std::vector<std::uint8_t> result(
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
            bytes_.begin() + static_cast<std::ptrdiff_t>(position_ + size));
        position_ += checked_size(size, description);
        return result;
    }

    bool empty() const { return position_ == bytes_.size(); }

  private:
    void require(std::size_t size, const char *description) const {
        if (position_ > bytes_.size() || size > bytes_.size() - position_) {
            throw std::runtime_error(std::string("truncated ") +
                                     description);
        }
    }

    std::span<const std::uint8_t> bytes_;
    std::size_t position_ = 0;
};

BasePreprocessingBundleFile read_bundle_file(ByteReader &reader) {
    BasePreprocessingBundleFile result;
    result.filename = reader.string("preprocessing bundle filename");
    result.serialized_bytes = reader.u64("preprocessing bundle size");
    result.file_digest = reader.digest("preprocessing bundle digest");
    result.bundle_identity =
        reader.digest("preprocessing bundle identity");
    if (!valid_filename(result.filename) || result.serialized_bytes == 0 ||
        is_zero(result.file_digest) || is_zero(result.bundle_identity)) {
        throw std::runtime_error(
            "invalid preprocessing bundle descriptor");
    }
    return result;
}

BasePreprocessingManifest parse_manifest(
    const std::filesystem::path &directory,
    std::span<const std::uint8_t> encoded) {
    constexpr std::size_t kHeaderBytes =
        kManifestMagic.size() + 3 * sizeof(std::uint64_t) + Digest{}.size();
    if (encoded.size() < kHeaderBytes + Digest{}.size() ||
        !std::equal(kManifestMagic.begin(), kManifestMagic.end(),
                    encoded.begin())) {
        throw std::runtime_error("invalid Base preprocessing manifest");
    }
    const std::size_t prefix_size = encoded.size() - Digest{}.size();
    Digest checksum{};
    std::copy_n(encoded.begin() + static_cast<std::ptrdiff_t>(prefix_size),
                checksum.size(), checksum.begin());
    if (domain_hash(kManifestChecksumDomain, encoded.first(prefix_size)) !=
        checksum) {
        throw std::runtime_error(
            "Base preprocessing manifest checksum mismatch");
    }

    ByteReader header(encoded.subspan(kManifestMagic.size(),
                                      kHeaderBytes - kManifestMagic.size()));
    const std::uint64_t version =
        header.u64("preprocessing manifest version");
    const std::uint64_t flags =
        header.u64("preprocessing manifest flags");
    const Digest identity = header.digest("preprocessing manifest identity");
    const std::uint64_t body_size =
        header.u64("preprocessing manifest body size");
    if (!header.empty() || version != kBasePreprocessingManifestVersion ||
        flags > 1 || is_zero(identity) ||
        body_size != prefix_size - kHeaderBytes) {
        throw std::runtime_error(
            "unsupported or malformed Base preprocessing manifest");
    }
    const auto body = encoded.subspan(kHeaderBytes,
                                      checked_size(body_size,
                                                   "manifest body size"));
    if (domain_hash(kManifestIdentityDomain, body) != identity) {
        throw std::runtime_error(
            "Base preprocessing manifest identity mismatch");
    }

    ByteReader reader(body);
    BasePreprocessingManifest result;
    result.manifest_directory = directory;
    result.format_version = version;
    result.identity = identity;
    result.public_setup_digest = reader.digest("PublicSetup digest");
    result.payload_digest = reader.digest("payload digest");
    result.layered_digest = reader.digest("layered digest");
    result.circuit_digest = reader.digest("combined circuit digest");
    result.bundle_identity = reader.digest("common bundle identity");
    result.public_setup_canonical =
        reader.byte_vector("canonical PublicSetup");
    result.evaluation_bundle = read_bundle_file(reader);
    result.client_bundle = read_bundle_file(reader);
    if (flags != 0) {
        result.prepared_plaintext_cache =
            BasePreparedPlaintextCacheMetadata{
                reader.u64("prepared logical plaintexts"),
                reader.u64("prepared level representations"),
                reader.u64("prepared NTT coefficient bytes")};
    }
    if (!reader.empty() || is_zero(result.public_setup_digest) ||
        is_zero(result.payload_digest) || is_zero(result.layered_digest) ||
        is_zero(result.circuit_digest) || is_zero(result.bundle_identity) ||
        result.evaluation_bundle.bundle_identity != result.bundle_identity ||
        result.client_bundle.bundle_identity != result.bundle_identity ||
        sha256(result.public_setup_canonical) !=
            result.public_setup_digest) {
        throw std::runtime_error(
            "Base preprocessing manifest semantic binding is invalid");
    }
    validate_cache_metadata(result.prepared_plaintext_cache);
    result.manifest_bytes =
        checked_u64(encoded.size(), "preprocessing manifest size");
    return result;
}

std::vector<std::uint8_t> read_manifest_file(
    const std::filesystem::path &path, std::uint64_t max_bytes) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path);
    if (!std::filesystem::is_regular_file(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::runtime_error(
            "Base preprocessing manifest is missing or non-regular");
    }
    const std::uintmax_t size = std::filesystem::file_size(path);
    if (max_bytes == 0 || size == 0 || size > max_bytes ||
        size > std::numeric_limits<std::size_t>::max() ||
        size > static_cast<std::uintmax_t>(
                   std::numeric_limits<std::streamsize>::max())) {
        throw std::invalid_argument(
            "Base preprocessing manifest exceeds its open limit");
    }
    std::vector<std::uint8_t> result(static_cast<std::size_t>(size));
    std::ifstream input(path, std::ios::binary);
    input.read(reinterpret_cast<char *>(result.data()),
               static_cast<std::streamsize>(result.size()));
    if (!input || input.peek() != std::ifstream::traits_type::eof()) {
        throw std::runtime_error(
            "Base preprocessing manifest changed during read");
    }
    return result;
}

void write_file_exclusive(const std::filesystem::path &path,
                          std::span<const std::uint8_t> value) {
#ifndef _WIN32
    int descriptor = ::open(path.c_str(),
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        throw std::filesystem::filesystem_error(
            "failed to create Base preprocessing manifest staging file",
            path, std::error_code(errno, std::generic_category()));
    }
    std::size_t offset = 0;
    try {
        while (offset < value.size()) {
            const ssize_t written = ::write(
                descriptor, value.data() + offset, value.size() - offset);
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                throw std::filesystem::filesystem_error(
                    "failed to write Base preprocessing manifest", path,
                    std::error_code(errno, std::generic_category()));
            }
            offset += static_cast<std::size_t>(written);
        }
        if (::close(descriptor) != 0) {
            descriptor = -1;
            throw std::filesystem::filesystem_error(
                "failed to close Base preprocessing manifest", path,
                std::error_code(errno, std::generic_category()));
        }
        descriptor = -1;
    } catch (...) {
        if (descriptor >= 0) {
            (void)::close(descriptor);
        }
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        throw;
    }
#else
    if (std::filesystem::exists(path)) {
        throw std::runtime_error(
            "Base preprocessing manifest staging file already exists");
    }
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char *>(value.data()),
                 static_cast<std::streamsize>(value.size()));
    output.close();
    if (!output) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        throw std::runtime_error(
            "failed to write Base preprocessing manifest");
    }
#endif
}

void publish_no_replace(const std::filesystem::path &partial,
                        const std::filesystem::path &complete) {
    std::filesystem::create_hard_link(partial, complete);
    if (!std::filesystem::remove(partial)) {
        throw std::runtime_error(
            "failed to remove Base preprocessing manifest staging link");
    }
}

void require_setup_binding(const PublicSetup &setup,
                           const payload::PayloadCircuit &payload,
                           const payload::LayeredCircuit &layered,
                           const BasePreprocessingManifest &manifest) {
    setup.validate(payload, layered);
    const std::vector<std::uint8_t> canonical = encode_canonical(setup);
    if (manifest.public_setup_canonical != canonical ||
        manifest.public_setup_digest != setup_digest(setup) ||
        manifest.payload_digest != payload::digest(payload) ||
        manifest.layered_digest != payload::digest(layered) ||
        manifest.circuit_digest != payload::combined_digest(payload,
                                                             layered)) {
        throw std::invalid_argument(
            "Base preprocessing manifest belongs to another setup or "
            "circuit");
    }
}

} // namespace

BasePreprocessingManifest publish_base_preprocessing_manifest(
    const PublicSetup &setup, const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    const BasePreprocessingManifestOptions &options) {
    if (options.max_manifest_bytes == 0 || options.max_bundle_bytes == 0 ||
        options.min_free_bytes == 0) {
        throw std::invalid_argument(
            "Base preprocessing publication limits must be nonzero");
    }
    validate_cache_metadata(options.prepared_plaintext_cache);
    setup.validate(payload, layered);
    const std::filesystem::path directory =
        normalize_directory(options.manifest_directory);
    const std::filesystem::path evaluation_path = normalize_role_bundle(
        options.evaluation_bundle_path, "evaluation bundle");
    const std::filesystem::path client_path = normalize_role_bundle(
        options.client_bundle_path, "client bundle");
    if (evaluation_path.parent_path() == client_path.parent_path() ||
        evaluation_path.parent_path() == directory ||
        client_path.parent_path() == directory) {
        throw std::invalid_argument(
            "manifest, evaluation, and client preprocessing directories "
            "must be disjoint");
    }
    require_directory_entries(directory, {});
    require_directory_entries(evaluation_path.parent_path(),
                              {evaluation_path.filename().string()});
    require_directory_entries(client_path.parent_path(),
                              {client_path.filename().string()});

    BasePreprocessingManifest result;
    result.manifest_directory = directory;
    result.public_setup_canonical = encode_canonical(setup);
    result.public_setup_digest = setup_digest(setup);
    result.payload_digest = payload::digest(payload);
    result.layered_digest = payload::digest(layered);
    result.circuit_digest = payload::combined_digest(payload, layered);
    result.evaluation_bundle = inspect_bundle(
        evaluation_path, options.max_bundle_bytes, BundleRole::Evaluation);
    result.client_bundle = inspect_bundle(
        client_path, options.max_bundle_bytes, BundleRole::Client);
    if (result.evaluation_bundle.bundle_identity !=
        result.client_bundle.bundle_identity) {
        throw std::invalid_argument(
            "evaluation and client SEAL bundle identities differ");
    }
    result.bundle_identity = result.evaluation_bundle.bundle_identity;
    result.prepared_plaintext_cache = options.prepared_plaintext_cache;

    const std::vector<std::uint8_t> encoded = encode_manifest(result);
    if (result.manifest_bytes > options.max_manifest_bytes) {
        throw std::invalid_argument(
            "Base preprocessing manifest exceeds its publication limit");
    }
    const std::filesystem::space_info space =
        std::filesystem::space(directory);
    const std::uint64_t required = checked_add(
        result.manifest_bytes, options.min_free_bytes,
        "Base preprocessing publication free-space requirement");
    if (space.available < required) {
        throw std::runtime_error(
            "insufficient free space for Base preprocessing manifest");
    }

    const std::filesystem::path partial = directory / "manifest.partial";
    const std::filesystem::path complete = directory / "manifest.bin";
    try {
        write_file_exclusive(partial, encoded);
        publish_no_replace(partial, complete);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(partial, ignored);
        throw;
    }
    return result;
}

BasePreprocessingManifest open_base_preprocessing_manifest(
    const std::filesystem::path &selected_directory,
    const PublicSetup &expected_setup,
    const payload::PayloadCircuit &expected_payload,
    const payload::LayeredCircuit &expected_layered,
    const BasePreprocessingManifestOpenLimits &limits) {
    if (limits.max_manifest_bytes == 0) {
        throw std::invalid_argument(
            "Base preprocessing manifest open limit must be nonzero");
    }
    const std::filesystem::path directory =
        normalize_directory(selected_directory);
    const std::vector<std::uint8_t> encoded = read_manifest_file(
        directory / "manifest.bin", limits.max_manifest_bytes);
    BasePreprocessingManifest result =
        parse_manifest(directory, encoded);
    require_setup_binding(expected_setup, expected_payload,
                          expected_layered, result);
    require_directory_entries(directory, {"manifest.bin"});
    return result;
}

OpenedBaseServerPreprocessing open_server_base_preprocessing(
    const std::filesystem::path &manifest_directory,
    const std::filesystem::path &selected_evaluation_bundle,
    const PublicSetup &expected_setup,
    const payload::PayloadCircuit &expected_payload,
    const payload::LayeredCircuit &expected_layered,
    const BasePreprocessingManifestOpenLimits &limits) {
    BasePreprocessingManifest manifest = open_base_preprocessing_manifest(
        manifest_directory, expected_setup, expected_payload,
        expected_layered, limits);
    if (limits.max_bundle_bytes == 0) {
        throw std::invalid_argument(
            "Base preprocessing bundle open limit must be nonzero");
    }
    const std::filesystem::path evaluation_path = normalize_role_bundle(
        selected_evaluation_bundle, "evaluation bundle");
    if (evaluation_path.parent_path() == manifest.manifest_directory ||
        evaluation_path.filename().string() !=
            manifest.evaluation_bundle.filename) {
        throw std::invalid_argument(
            "evaluation bundle path disagrees with the shared manifest");
    }
    require_directory_entries(evaluation_path.parent_path(),
                              {evaluation_path.filename().string()});
    const BasePreprocessingBundleFile evaluation = inspect_bundle(
        evaluation_path, limits.max_bundle_bytes, BundleRole::Evaluation);
    if (evaluation != manifest.evaluation_bundle ||
        evaluation.bundle_identity != manifest.bundle_identity) {
        throw std::runtime_error(
            "evaluation bundle no longer matches its shared manifest");
    }
    return OpenedBaseServerPreprocessing{std::move(manifest),
                                         evaluation_path};
}

OpenedBaseClientPreprocessing open_client_base_preprocessing(
    const std::filesystem::path &manifest_directory,
    const std::filesystem::path &selected_client_bundle,
    const PublicSetup &expected_setup,
    const payload::PayloadCircuit &expected_payload,
    const payload::LayeredCircuit &expected_layered,
    const BasePreprocessingManifestOpenLimits &limits) {
    BasePreprocessingManifest manifest = open_base_preprocessing_manifest(
        manifest_directory, expected_setup, expected_payload,
        expected_layered, limits);
    if (limits.max_bundle_bytes == 0) {
        throw std::invalid_argument(
            "Base preprocessing bundle open limit must be nonzero");
    }
    const std::filesystem::path client_path = normalize_role_bundle(
        selected_client_bundle, "client bundle");
    if (client_path.parent_path() == manifest.manifest_directory ||
        client_path.filename().string() !=
            manifest.client_bundle.filename) {
        throw std::invalid_argument(
            "client bundle path disagrees with the shared manifest");
    }
    require_directory_entries(client_path.parent_path(),
                              {client_path.filename().string()});
    const BasePreprocessingBundleFile client = inspect_bundle(
        client_path, limits.max_bundle_bytes, BundleRole::Client);
    if (client != manifest.client_bundle ||
        client.bundle_identity != manifest.bundle_identity) {
        throw std::runtime_error(
            "client bundle no longer matches its shared manifest");
    }
    return OpenedBaseClientPreprocessing{std::move(manifest), client_path};
}

} // namespace laminate::protocol
