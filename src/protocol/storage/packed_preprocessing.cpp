/// @file packed_preprocessing.cpp
/// @brief Fixed-name, manifest-last packed preprocessing storage.

#include "laminate/protocol/storage/packed_preprocessing.hpp"

#include "../codec/bounded_binary.hpp"

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
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

namespace laminate::protocol {
namespace {

using Bytes = codec::Bytes;
using codec::checked_u64;

constexpr std::array<std::uint8_t, 8> kRoleMagic{
    'L', 'M', 'P', 'R', 'L', 'M', '0', '2'};
constexpr std::array<std::uint8_t, 8> kRootMagic{
    'L', 'M', 'P', 'R', 'T', 'M', '0', '2'};
constexpr std::string_view kRoleSemanticDomain =
    "LaminateImpl/PackedRoleManifestSemantic/v2";
constexpr std::string_view kRoleStorageDomain =
    "LaminateImpl/PackedRoleManifestStorage/v2";
constexpr std::string_view kRoleChecksumDomain =
    "LaminateImpl/PackedRoleManifestChecksum/v2";
constexpr std::string_view kRootSemanticDomain =
    "LaminateImpl/PackedRootManifestSemantic/v2";
constexpr std::string_view kRootStorageDomain =
    "LaminateImpl/PackedRootManifestStorage/v2";
constexpr std::string_view kRootChecksumDomain =
    "LaminateImpl/PackedRootManifestChecksum/v2";
constexpr std::string_view kTreeLayoutDomain =
    "LaminateImpl/PackedRoleArtifactTreeLayout/v1";

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

bool is_zero(const Digest &value) {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

bool same_bytes(const Bytes &left,
                std::span<const std::uint8_t> right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin());
}

std::size_t checked_size(std::uint64_t value,
                         const char *description) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string(description) +
                                    " does not fit size_t");
    }
    return static_cast<std::size_t>(value);
}

class Writer final : public codec::Writer {
  public:
    void string(std::string_view value) {
        u64(checked_u64(value.size(), "encoded string"));
        raw(bytes(value));
    }
    void digest(const Digest &value) { raw(value); }
};

class Reader final : public codec::Reader {
  public:
    using codec::Reader::Reader;

    Digest digest(const char *description) {
        Digest result{};
        const auto encoded = take(result.size(), description);
        std::copy(encoded.begin(), encoded.end(), result.begin());
        return result;
    }
    std::string string(std::uint64_t maximum,
                       const char *description) {
        const std::uint64_t count = u64(description);
        if (count == 0 || count > maximum) {
            throw std::invalid_argument(std::string(description) +
                                        " exceeds its byte limit");
        }
        const auto encoded = take(checked_size(count, description),
                                  description);
        return std::string(reinterpret_cast<const char *>(encoded.data()),
                           encoded.size());
    }
    void finish() const {
        codec::Reader::finish("packed manifest has trailing data");
    }
};

std::filesystem::path normalize_directory(
    const std::filesystem::path &directory) {
    const auto status = std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(
            "packed preprocessing path is not a regular directory");
    }
    return std::filesystem::canonical(directory);
}

bool path_contains(const std::filesystem::path &ancestor,
                   const std::filesystem::path &descendant) {
    auto left = ancestor.begin();
    auto right = descendant.begin();
    for (; left != ancestor.end(); ++left, ++right) {
        if (right == descendant.end() || *left != *right) {
            return false;
        }
    }
    return true;
}

bool directories_overlap(const std::filesystem::path &left,
                         const std::filesystem::path &right) {
    return path_contains(left, right) || path_contains(right, left);
}

void require_entries(const std::filesystem::path &directory,
                     std::initializer_list<std::string_view> expected) {
    std::set<std::string> names;
    for (std::string_view name : expected) {
        names.emplace(name);
    }
    for (const auto &entry :
         std::filesystem::directory_iterator(directory)) {
        const std::string name = entry.path().filename().string();
        const auto selected = names.find(name);
        if (name.empty() || name == "." || name == ".." ||
            name.find('/') != std::string::npos ||
            selected == names.end()) {
            throw std::invalid_argument(
                "packed preprocessing directory contains unowned files");
        }
        names.erase(selected);
    }
    if (!names.empty()) {
        throw std::invalid_argument(
            "packed preprocessing directory contains unowned files");
    }
}

std::filesystem::path fixed_file(const std::filesystem::path &directory,
                                 std::string_view filename,
                                 const char *description) {
    const std::filesystem::path path = directory / std::string(filename);
    const auto status = std::filesystem::symlink_status(path);
    if (!std::filesystem::is_regular_file(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(std::string(description) +
                                    " is not a regular fixed-name file");
    }
    const std::filesystem::path canonical =
        std::filesystem::canonical(path);
    if (canonical.parent_path() != directory ||
        canonical.filename() != filename) {
        throw std::invalid_argument(std::string(description) +
                                    " escapes its role directory");
    }
    std::error_code link_error;
    const std::uintmax_t links =
        std::filesystem::hard_link_count(canonical, link_error);
    if (link_error || links != 1U) {
        throw std::invalid_argument(std::string(description) +
                                    " has aliased hard links");
    }
    return canonical;
}

std::filesystem::path fixed_directory(
    const std::filesystem::path &directory,
    std::string_view filename,
    const char *description) {
    const std::filesystem::path path = directory / std::string(filename);
    const auto status = std::filesystem::symlink_status(path);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(std::string(description) +
                                    " is not a fixed-name real directory");
    }
    const std::filesystem::path canonical =
        std::filesystem::canonical(path);
    if (canonical.parent_path() != directory ||
        canonical.filename() != filename) {
        throw std::invalid_argument(std::string(description) +
                                    " escapes its role directory");
    }
    return canonical;
}

struct InspectedFile {
    std::uint64_t serialized_bytes = 0;
    Digest digest{};
};

std::uint64_t bounded_file_size(const std::filesystem::path &path,
                                std::uint64_t maximum,
                                const char *description) {
    const auto status = std::filesystem::symlink_status(path);
    if (!std::filesystem::is_regular_file(status) ||
        std::filesystem::is_symlink(status)) {
        throw std::invalid_argument(std::string(description) +
                                    " is not a regular file");
    }
    std::error_code link_error;
    const std::uintmax_t links =
        std::filesystem::hard_link_count(path, link_error);
    if (link_error || links != 1U) {
        throw std::invalid_argument(std::string(description) +
                                    " has aliased hard links");
    }
    const std::uintmax_t size = std::filesystem::file_size(path);
    if (maximum == 0 || size > maximum ||
        size > std::numeric_limits<std::uint64_t>::max() ||
        size > static_cast<std::uintmax_t>(
                   std::numeric_limits<std::streamoff>::max())) {
        throw std::invalid_argument(std::string(description) +
                                    " exceeds its byte limit");
    }
    return static_cast<std::uint64_t>(size);
}

InspectedFile inspect_file(const std::filesystem::path &path,
                           std::uint64_t maximum,
                           const char *description) {
    const std::uint64_t expected =
        bounded_file_size(path, maximum, description);
    const auto modified = std::filesystem::last_write_time(path);
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error(std::string("failed to open ") +
                                 description);
    }
    Sha256Hasher hasher;
    std::array<std::uint8_t, 64ULL << 10U> buffer{};
    std::uint64_t consumed = 0;
    while (consumed < expected) {
        const std::size_t chunk = static_cast<std::size_t>(
            std::min<std::uint64_t>(expected - consumed, buffer.size()));
        input.read(reinterpret_cast<char *>(buffer.data()),
                   static_cast<std::streamsize>(chunk));
        if (!input) {
            throw std::runtime_error(std::string(description) +
                                     " is truncated");
        }
        hasher.update(std::span<const std::uint8_t>(buffer).first(chunk));
        consumed += chunk;
    }
    if (input.peek() != std::ifstream::traits_type::eof() ||
        std::filesystem::file_size(path) != expected ||
        std::filesystem::last_write_time(path) != modified ||
        !std::filesystem::is_regular_file(
            std::filesystem::symlink_status(path)) ||
        std::filesystem::is_symlink(
            std::filesystem::symlink_status(path)) ||
        std::filesystem::hard_link_count(path) != 1U) {
        throw std::runtime_error(std::string(description) +
                                 " changed while it was inspected");
    }
    return InspectedFile{expected, hasher.finish()};
}

struct ArtifactTreeLimits {
    std::uint64_t max_files = 0;
    std::uint64_t max_directories = 0;
    std::uint64_t max_depth = 0;
    std::uint64_t max_relative_path_bytes = 0;
    std::uint64_t max_file_bytes = 0;
    std::uint64_t max_total_bytes = 0;
    std::uint64_t max_manifest_bytes = 0;
};

ArtifactTreeLimits artifact_tree_limits(
    const PackedPreprocessingPublishLimits &limits) {
    return ArtifactTreeLimits{
        limits.max_artifact_tree_files,
        limits.max_artifact_tree_directories,
        limits.max_artifact_tree_depth,
        limits.max_artifact_tree_relative_path_bytes,
        limits.max_artifact_tree_file_bytes,
        limits.max_artifact_tree_bytes,
        limits.max_manifest_bytes};
}

ArtifactTreeLimits artifact_tree_limits(
    const PackedPreprocessingOpenLimits &limits) {
    return ArtifactTreeLimits{
        limits.max_artifact_tree_files,
        limits.max_artifact_tree_directories,
        limits.max_artifact_tree_depth,
        limits.max_artifact_tree_relative_path_bytes,
        limits.max_artifact_tree_file_bytes,
        limits.max_artifact_tree_bytes,
        limits.max_manifest_bytes};
}

std::uint64_t checked_add(std::uint64_t left,
                          std::uint64_t right,
                          const char *description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left + right;
}

bool canonical_tree_component(std::string_view component) {
    if (component.empty() || component == "." || component == "..") {
        return false;
    }
    return std::all_of(component.begin(), component.end(), [](char value) {
        const unsigned char byte = static_cast<unsigned char>(value);
        return (byte >= 'a' && byte <= 'z') ||
               (byte >= 'A' && byte <= 'Z') ||
               (byte >= '0' && byte <= '9') || value == '-' ||
               value == '_' || value == '.';
    });
}

std::uint64_t validate_tree_relative_path(
    std::string_view path,
    const ArtifactTreeLimits &limits) {
    if (path.empty() || path.size() > limits.max_relative_path_bytes ||
        path.front() == '/' || path.back() == '/' ||
        path.find('\\') != std::string_view::npos) {
        throw std::invalid_argument(
            "packed artifact-tree path is not canonical");
    }
    std::uint64_t depth = 0;
    std::size_t begin = 0;
    while (begin < path.size()) {
        const std::size_t end = path.find('/', begin);
        const std::size_t stop =
            end == std::string_view::npos ? path.size() : end;
        if (!canonical_tree_component(path.substr(begin, stop - begin))) {
            throw std::invalid_argument(
                "packed artifact-tree path has a noncanonical component");
        }
        ++depth;
        if (depth > limits.max_depth) {
            throw std::invalid_argument(
                "packed artifact-tree path exceeds its depth limit");
        }
        if (end == std::string_view::npos) {
            break;
        }
        begin = end + 1U;
    }
    return depth;
}

Digest artifact_tree_layout_digest(
    const PackedStoredArtifactTree &tree) {
    Sha256Hasher hasher;
    hasher.update(bytes(kTreeLayoutDomain));
    Writer header;
    header.u64(tree.file_count);
    header.u64(tree.directory_count);
    header.u64(tree.serialized_bytes);
    hasher.update(header.view());
    for (const auto &entry : tree.entries) {
        Writer encoded;
        encoded.u64(static_cast<std::uint64_t>(entry.kind));
        encoded.string(entry.relative_path);
        encoded.u64(entry.serialized_bytes);
        encoded.digest(entry.file_digest);
        hasher.update(encoded.view());
    }
    return hasher.finish();
}

std::uint64_t artifact_tree_encoded_bytes(
    const PackedStoredArtifactTree &tree) {
    std::uint64_t result = 2U * sizeof(Digest) +
                           4U * sizeof(std::uint64_t);
    for (const auto &entry : tree.entries) {
        result = checked_add(result,
                             7U * sizeof(std::uint64_t) +
                                 checked_u64(entry.relative_path.size(),
                                             "artifact-tree path"),
                             "packed artifact-tree manifest bytes");
    }
    return result;
}

void validate_artifact_tree(PackedStoredArtifactTree &tree,
                            const ArtifactTreeLimits &limits) {
    if (is_zero(tree.semantic_identity) ||
        tree.file_count > limits.max_files ||
        tree.directory_count > limits.max_directories ||
        tree.serialized_bytes > limits.max_total_bytes ||
        artifact_tree_encoded_bytes(tree) > limits.max_manifest_bytes) {
        throw std::invalid_argument(
            "packed artifact tree exceeds its declared limits");
    }
    const std::uint64_t expected_entries = checked_add(
        tree.file_count, tree.directory_count,
        "packed artifact-tree entry count");
    if (expected_entries != checked_u64(tree.entries.size(),
                                        "packed artifact-tree entries")) {
        throw std::invalid_argument(
            "packed artifact-tree counts are inconsistent");
    }
    std::uint64_t files = 0;
    std::uint64_t directories = 0;
    std::uint64_t total_bytes = 0;
    std::string_view previous;
    bool has_previous = false;
    for (const auto &entry : tree.entries) {
        (void)validate_tree_relative_path(entry.relative_path, limits);
        if (has_previous && previous >= entry.relative_path) {
            throw std::invalid_argument(
                "packed artifact-tree entries are not canonical");
        }
        previous = entry.relative_path;
        has_previous = true;
        if (entry.kind == PackedArtifactTreeEntryKind::Directory) {
            ++directories;
            if (entry.serialized_bytes != 0 ||
                !is_zero(entry.file_digest)) {
                throw std::invalid_argument(
                    "packed artifact-tree directory carries file data");
            }
        } else if (entry.kind == PackedArtifactTreeEntryKind::File) {
            ++files;
            if (entry.serialized_bytes > limits.max_file_bytes) {
                throw std::invalid_argument(
                    "packed artifact-tree file exceeds its byte limit");
            }
            total_bytes = checked_add(
                total_bytes, entry.serialized_bytes,
                "packed artifact-tree aggregate bytes");
            if (total_bytes > limits.max_total_bytes) {
                throw std::invalid_argument(
                    "packed artifact tree exceeds its aggregate byte limit");
            }
        } else {
            throw std::invalid_argument(
                "packed artifact tree has an unknown entry kind");
        }
    }
    if (files != tree.file_count ||
        directories != tree.directory_count ||
        total_bytes != tree.serialized_bytes ||
        tree.layout_digest != artifact_tree_layout_digest(tree)) {
        throw std::invalid_argument(
            "packed artifact-tree commitment is inconsistent");
    }
}

PackedStoredArtifactTree inspect_artifact_tree(
    const std::filesystem::path &tree_root,
    const Digest &semantic_identity,
    const ArtifactTreeLimits &limits) {
    if (is_zero(semantic_identity)) {
        throw std::invalid_argument(
            "packed artifact-tree semantic identity must be nonzero");
    }
    struct PendingDirectory {
        std::filesystem::path path;
        std::string relative_path;
    };
    PackedStoredArtifactTree result;
    result.semantic_identity = semantic_identity;
    std::uint64_t encoded_tree_bytes =
        2U * sizeof(Digest) + 4U * sizeof(std::uint64_t);
    std::vector<PendingDirectory> pending{
        PendingDirectory{tree_root, std::string{}}};
    while (!pending.empty()) {
        PendingDirectory current = std::move(pending.back());
        pending.pop_back();
        const auto before = std::filesystem::last_write_time(current.path);
        for (const auto &filesystem_entry :
             std::filesystem::directory_iterator(current.path)) {
            const std::string name =
                filesystem_entry.path().filename().string();
            if (!canonical_tree_component(name)) {
                throw std::invalid_argument(
                    "packed artifact tree has a noncanonical filename");
            }
            const std::string relative =
                current.relative_path.empty()
                    ? name
                    : current.relative_path + "/" + name;
            (void)validate_tree_relative_path(relative, limits);
            encoded_tree_bytes = checked_add(
                encoded_tree_bytes,
                7U * sizeof(std::uint64_t) +
                    checked_u64(relative.size(), "artifact-tree path"),
                "packed artifact-tree manifest bytes");
            if (encoded_tree_bytes > limits.max_manifest_bytes) {
                throw std::invalid_argument(
                    "packed artifact tree exceeds its manifest byte limit");
            }
            const auto status =
                std::filesystem::symlink_status(filesystem_entry.path());
            if (std::filesystem::is_symlink(status)) {
                throw std::invalid_argument(
                    "packed artifact tree contains a symlink");
            }
            const std::filesystem::path canonical =
                std::filesystem::canonical(filesystem_entry.path());
            if (canonical.parent_path() != current.path ||
                canonical.filename() != name) {
                throw std::invalid_argument(
                    "packed artifact-tree entry escapes its parent");
            }
            if (std::filesystem::is_directory(status)) {
                result.directory_count = checked_add(
                    result.directory_count, 1,
                    "packed artifact-tree directory count");
                if (result.directory_count > limits.max_directories) {
                    throw std::invalid_argument(
                        "packed artifact tree exceeds its directory limit");
                }
                result.entries.push_back(PackedStoredArtifactTreeEntry{
                    PackedArtifactTreeEntryKind::Directory,
                    relative, 0, Digest{}});
                pending.push_back(
                    PendingDirectory{canonical, relative});
            } else if (std::filesystem::is_regular_file(status)) {
                result.file_count = checked_add(
                    result.file_count, 1,
                    "packed artifact-tree file count");
                if (result.file_count > limits.max_files) {
                    throw std::invalid_argument(
                        "packed artifact tree exceeds its file-count limit");
                }
                const InspectedFile inspected = inspect_file(
                    canonical, limits.max_file_bytes,
                    "packed artifact-tree file");
                result.serialized_bytes = checked_add(
                    result.serialized_bytes, inspected.serialized_bytes,
                    "packed artifact-tree aggregate bytes");
                if (result.serialized_bytes > limits.max_total_bytes) {
                    throw std::invalid_argument(
                        "packed artifact tree exceeds its aggregate byte limit");
                }
                result.entries.push_back(PackedStoredArtifactTreeEntry{
                    PackedArtifactTreeEntryKind::File,
                    relative, inspected.serialized_bytes,
                    inspected.digest});
            } else {
                throw std::invalid_argument(
                    "packed artifact tree contains a non-file entry");
            }
        }
        if (std::filesystem::last_write_time(current.path) != before ||
            !std::filesystem::is_directory(
                std::filesystem::symlink_status(current.path)) ||
            std::filesystem::is_symlink(
                std::filesystem::symlink_status(current.path))) {
            throw std::runtime_error(
                "packed artifact tree changed while it was inspected");
        }
    }
    std::sort(result.entries.begin(), result.entries.end(),
              [](const auto &left, const auto &right) {
                  return left.relative_path < right.relative_path;
              });
    result.layout_digest = artifact_tree_layout_digest(result);
    validate_artifact_tree(result, limits);
    return result;
}

Bytes read_file(const std::filesystem::path &path,
                std::uint64_t maximum, const char *description) {
    const std::uint64_t size = bounded_file_size(path, maximum, description);
    Bytes output(checked_size(size, description));
    const auto modified = std::filesystem::last_write_time(path);
    std::ifstream input(path, std::ios::binary);
    if (!input ||
        (size != 0 &&
         !input.read(reinterpret_cast<char *>(output.data()),
                     static_cast<std::streamsize>(size))) ||
        input.peek() != std::ifstream::traits_type::eof() ||
        std::filesystem::file_size(path) != size ||
        std::filesystem::last_write_time(path) != modified ||
        !std::filesystem::is_regular_file(
            std::filesystem::symlink_status(path)) ||
        std::filesystem::is_symlink(
            std::filesystem::symlink_status(path)) ||
        std::filesystem::hard_link_count(path) != 1U) {
        throw std::runtime_error(std::string(description) +
                                 " changed while it was read");
    }
    return output;
}

void require_free_space(const std::filesystem::path &directory,
                        std::uint64_t bytes_to_write,
                        std::uint64_t min_free_bytes) {
    const auto available = std::filesystem::space(directory).available;
    if (available < bytes_to_write ||
        available - bytes_to_write < min_free_bytes) {
        throw std::runtime_error(
            "packed preprocessing directory lacks its free-space floor");
    }
}

void publish_bytes(const std::filesystem::path &directory,
                   std::string_view filename,
                   std::span<const std::uint8_t> value,
                   std::uint64_t min_free_bytes) {
    require_free_space(directory, checked_u64(value.size(), "published file"),
                       min_free_bytes);
    const std::filesystem::path partial =
        directory / (std::string(filename) + ".partial");
    const std::filesystem::path final = directory / std::string(filename);
    if (std::filesystem::exists(std::filesystem::symlink_status(partial)) ||
        std::filesystem::exists(std::filesystem::symlink_status(final))) {
        throw std::invalid_argument(
            "packed preprocessing publication target already exists");
    }
#ifndef _WIN32
    const int descriptor = ::open(partial.c_str(),
                                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                                  0600);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "create packed preprocessing partial");
    }
    bool closed = false;
    bool final_linked = false;
    try {
        std::size_t written = 0;
        while (written < value.size()) {
            const ssize_t count = ::write(
                descriptor, value.data() + written, value.size() - written);
            if (count <= 0) {
                throw std::system_error(errno, std::generic_category(),
                                        "write packed preprocessing partial");
            }
            written += static_cast<std::size_t>(count);
        }
        if (::fsync(descriptor) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "sync packed preprocessing partial");
        }
        if (::close(descriptor) != 0) {
            closed = true;
            throw std::system_error(errno, std::generic_category(),
                                    "close packed preprocessing partial");
        }
        closed = true;
        if (::link(partial.c_str(), final.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "publish packed preprocessing file");
        }
        final_linked = true;
        if (::unlink(partial.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "remove packed preprocessing partial");
        }
    } catch (...) {
        if (!closed) {
            ::close(descriptor);
        }
        std::error_code ignored;
        if (final_linked) {
            std::filesystem::remove(final, ignored);
        }
        std::filesystem::remove(partial, ignored);
        throw;
    }
#else
    bool final_linked = false;
    try {
        std::ofstream output(partial, std::ios::binary | std::ios::out);
        if (!output ||
            (value.size() != 0 &&
             !output.write(reinterpret_cast<const char *>(value.data()),
                           static_cast<std::streamsize>(value.size())))) {
            throw std::runtime_error(
                "failed to write packed preprocessing partial");
        }
        output.close();
        if (!output) {
            throw std::runtime_error(
                "failed to close packed preprocessing partial");
        }
        std::filesystem::create_hard_link(partial, final);
        final_linked = true;
        std::filesystem::remove(partial);
    } catch (...) {
        std::error_code ignored;
        if (final_linked) {
            std::filesystem::remove(final, ignored);
        }
        std::filesystem::remove(partial, ignored);
        throw;
    }
#endif
}

Digest role_semantic_identity(PackedPreprocessingRole role,
                              const Digest &workload,
                              const Digest &artifact,
                              const Digest &artifact_tree) {
    Writer writer;
    writer.u64(static_cast<std::uint64_t>(role));
    writer.digest(workload);
    writer.digest(artifact);
    writer.digest(artifact_tree);
    return domain_hash(kRoleSemanticDomain, writer.view());
}

Digest role_storage_identity(const Digest &semantic,
                             const PackedStoredArtifact &artifact,
                             const PackedStoredArtifactTree &tree) {
    Writer writer;
    writer.digest(semantic);
    writer.u64(artifact.serialized_bytes);
    writer.digest(artifact.file_digest);
    writer.u64(tree.file_count);
    writer.u64(tree.directory_count);
    writer.u64(tree.serialized_bytes);
    writer.digest(tree.layout_digest);
    return domain_hash(kRoleStorageDomain, writer.view());
}

void encode_artifact_tree(Writer &writer,
                          const PackedStoredArtifactTree &tree) {
    writer.digest(tree.semantic_identity);
    writer.u64(tree.file_count);
    writer.u64(tree.directory_count);
    writer.u64(tree.serialized_bytes);
    writer.digest(tree.layout_digest);
    writer.u64(checked_u64(tree.entries.size(),
                           "packed artifact-tree entries"));
    for (const auto &entry : tree.entries) {
        writer.u64(static_cast<std::uint64_t>(entry.kind));
        writer.string(entry.relative_path);
        writer.u64(entry.serialized_bytes);
        writer.digest(entry.file_digest);
    }
}

PackedStoredArtifactTree decode_artifact_tree(
    Reader &reader,
    const ArtifactTreeLimits &limits) {
    PackedStoredArtifactTree result;
    result.semantic_identity =
        reader.digest("artifact-tree semantic identity");
    result.file_count = reader.u64("artifact-tree file count");
    result.directory_count =
        reader.u64("artifact-tree directory count");
    result.serialized_bytes =
        reader.u64("artifact-tree aggregate bytes");
    result.layout_digest = reader.digest("artifact-tree layout digest");
    if (result.file_count > limits.max_files ||
        result.directory_count > limits.max_directories ||
        result.serialized_bytes > limits.max_total_bytes) {
        throw std::invalid_argument(
            "packed artifact tree exceeds its decode limits");
    }
    const std::uint64_t expected_entries = checked_add(
        result.file_count, result.directory_count,
        "packed artifact-tree entry count");
    const std::uint64_t entry_count =
        reader.u64("artifact-tree entry count");
    if (entry_count != expected_entries) {
        throw std::invalid_argument(
            "packed artifact-tree encoded count is inconsistent");
    }
    result.entries.reserve(checked_size(entry_count,
                                        "artifact-tree entry count"));
    for (std::uint64_t index = 0; index < entry_count; ++index) {
        const std::uint64_t kind_word =
            reader.u64("artifact-tree entry kind");
        if (kind_word != static_cast<std::uint64_t>(
                             PackedArtifactTreeEntryKind::Directory) &&
            kind_word != static_cast<std::uint64_t>(
                             PackedArtifactTreeEntryKind::File)) {
            throw std::invalid_argument(
                "packed artifact tree has an unknown entry kind");
        }
        PackedStoredArtifactTreeEntry entry;
        entry.kind = static_cast<PackedArtifactTreeEntryKind>(kind_word);
        entry.relative_path = reader.string(
            limits.max_relative_path_bytes,
            "artifact-tree relative path");
        entry.serialized_bytes =
            reader.u64("artifact-tree entry bytes");
        entry.file_digest = reader.digest("artifact-tree file digest");
        result.entries.push_back(std::move(entry));
    }
    validate_artifact_tree(result, limits);
    return result;
}

std::uint64_t role_manifest_encoded_bytes(
    const PackedRoleManifest &manifest) {
    constexpr std::uint64_t fixed_bytes =
        8U + 3U * sizeof(std::uint64_t) +
        3U * sizeof(Digest) + sizeof(std::uint64_t) +
        3U * sizeof(Digest);
    return checked_add(fixed_bytes,
                       artifact_tree_encoded_bytes(manifest.artifact_tree),
                       "packed role manifest bytes");
}

Bytes encode_role_manifest(const PackedRoleManifest &manifest) {
    const Digest semantic = role_semantic_identity(
        manifest.role, manifest.workload_semantic_identity,
        manifest.role_artifact.semantic_identity,
        manifest.artifact_tree.semantic_identity);
    const Digest storage =
        role_storage_identity(semantic, manifest.role_artifact,
                              manifest.artifact_tree);
    if (semantic != manifest.semantic_identity ||
        storage != manifest.storage_identity) {
        throw std::logic_error("inconsistent packed role-manifest identity");
    }
    Writer writer;
    writer.raw(kRoleMagic);
    writer.u64(kPackedRoleManifestVersion);
    writer.u64(0);
    writer.u64(static_cast<std::uint64_t>(manifest.role));
    writer.digest(manifest.workload_semantic_identity);
    writer.digest(manifest.role_artifact.semantic_identity);
    writer.u64(manifest.role_artifact.serialized_bytes);
    writer.digest(manifest.role_artifact.file_digest);
    encode_artifact_tree(writer, manifest.artifact_tree);
    writer.digest(semantic);
    writer.digest(storage);
    writer.digest(domain_hash(kRoleChecksumDomain, writer.view()));
    return std::move(writer).finish();
}

PackedRoleManifest decode_role_manifest(
    std::span<const std::uint8_t> encoded,
    const std::filesystem::path &directory,
    const ArtifactTreeLimits &tree_limits) {
    Reader reader(encoded);
    const auto magic = reader.take(kRoleMagic.size(), "role-manifest magic");
    if (!std::equal(kRoleMagic.begin(), kRoleMagic.end(), magic.begin()) ||
        reader.u64("role-manifest version") !=
            kPackedRoleManifestVersion ||
        reader.u64("role-manifest flags") != 0U) {
        throw std::invalid_argument("unsupported packed role manifest");
    }
    const std::uint64_t role_word = reader.u64("preprocessing role");
    if (role_word != static_cast<std::uint64_t>(
                         PackedPreprocessingRole::Server) &&
        role_word != static_cast<std::uint64_t>(
                         PackedPreprocessingRole::Client)) {
        throw std::invalid_argument("unknown packed preprocessing role");
    }
    PackedRoleManifest result;
    result.directory = directory;
    result.role = static_cast<PackedPreprocessingRole>(role_word);
    result.workload_semantic_identity =
        reader.digest("role workload identity");
    result.role_artifact.semantic_identity =
        reader.digest("role artifact semantic identity");
    result.role_artifact.serialized_bytes =
        reader.u64("role artifact byte count");
    result.role_artifact.file_digest =
        reader.digest("role artifact file digest");
    result.artifact_tree = decode_artifact_tree(reader, tree_limits);
    result.semantic_identity = reader.digest("role semantic identity");
    result.storage_identity = reader.digest("role storage identity");
    const std::size_t checksum_offset = reader.position();
    const Digest checksum = reader.digest("role-manifest checksum");
    reader.finish();
    result.manifest_bytes = checked_u64(encoded.size(), "role manifest");
    if (result.semantic_identity != role_semantic_identity(
            result.role, result.workload_semantic_identity,
            result.role_artifact.semantic_identity,
            result.artifact_tree.semantic_identity) ||
        result.storage_identity != role_storage_identity(
            result.semantic_identity, result.role_artifact,
            result.artifact_tree) ||
        checksum != domain_hash(kRoleChecksumDomain,
                                encoded.first(checksum_offset)) ||
        !same_bytes(encode_role_manifest(result), encoded)) {
        throw std::invalid_argument(
            "packed role manifest is noncanonical or corrupted");
    }
    return result;
}

struct OpenedRoleInternal {
    PackedRoleManifest manifest;
    std::filesystem::path artifact_path;
    std::filesystem::path artifact_tree_path;
    Digest manifest_file_digest{};
};

OpenedRoleInternal open_role_internal(
    const std::filesystem::path &selected_directory,
    PackedPreprocessingRole expected_role,
    const Digest &expected_workload_identity,
    const PackedRootRoleBinding *expected_binding,
    const PackedPreprocessingOpenLimits &limits) {
    const std::filesystem::path directory =
        normalize_directory(selected_directory);
    require_entries(directory,
                    {kPackedRoleStaticFilename,
                     kPackedRoleArtifactTreeDirectory,
                     kPackedManifestFilename});
    const std::filesystem::path manifest_path = fixed_file(
        directory, kPackedManifestFilename, "packed role manifest");
    const Bytes encoded = read_file(manifest_path,
                                    limits.max_manifest_bytes,
                                    "packed role manifest");
    const Digest manifest_file_digest = sha256(encoded);
    PackedRoleManifest manifest =
        decode_role_manifest(encoded, directory,
                             artifact_tree_limits(limits));
    if (manifest.role != expected_role ||
        manifest.workload_semantic_identity !=
            expected_workload_identity ||
        (expected_binding &&
         (manifest.semantic_identity !=
              expected_binding->semantic_identity ||
          manifest.storage_identity !=
              expected_binding->storage_identity ||
          manifest.manifest_bytes !=
              expected_binding->manifest_bytes ||
          manifest_file_digest !=
              expected_binding->manifest_file_digest))) {
        throw std::invalid_argument(
            "packed role manifest has the wrong root binding");
    }
    const std::filesystem::path artifact_path = fixed_file(
        directory, kPackedRoleStaticFilename, "packed role artifact");
    const InspectedFile artifact = inspect_file(
        artifact_path, limits.max_role_artifact_bytes,
        "packed role artifact");
    if (artifact.serialized_bytes !=
            manifest.role_artifact.serialized_bytes ||
        artifact.digest != manifest.role_artifact.file_digest) {
        throw std::invalid_argument(
            "packed role artifact differs from its manifest");
    }
    const std::filesystem::path tree_path = fixed_directory(
        directory, kPackedRoleArtifactTreeDirectory,
        "packed role artifact tree");
    const PackedStoredArtifactTree inspected_tree = inspect_artifact_tree(
        tree_path, manifest.artifact_tree.semantic_identity,
        artifact_tree_limits(limits));
    if (inspected_tree != manifest.artifact_tree) {
        throw std::invalid_argument(
            "packed artifact tree differs from its manifest");
    }
    return OpenedRoleInternal{std::move(manifest), artifact_path,
                              tree_path, manifest_file_digest};
}

Digest root_semantic_identity(const PackedRootManifest &manifest) {
    Writer writer;
    writer.digest(manifest.workload.semantic_identity);
    writer.digest(manifest.server.semantic_identity);
    writer.digest(manifest.client.semantic_identity);
    return domain_hash(kRootSemanticDomain, writer.view());
}

Digest root_storage_identity(const PackedRootManifest &manifest,
                             const Digest &semantic) {
    Writer writer;
    writer.digest(semantic);
    writer.u64(manifest.workload.serialized_bytes);
    writer.digest(manifest.workload.file_digest);
    writer.digest(manifest.server.storage_identity);
    writer.u64(manifest.server.manifest_bytes);
    writer.digest(manifest.server.manifest_file_digest);
    writer.digest(manifest.client.storage_identity);
    writer.u64(manifest.client.manifest_bytes);
    writer.digest(manifest.client.manifest_file_digest);
    return domain_hash(kRootStorageDomain, writer.view());
}

void encode_root_role(Writer &writer,
                      const PackedRootRoleBinding &binding) {
    writer.digest(binding.semantic_identity);
    writer.digest(binding.storage_identity);
    writer.u64(binding.manifest_bytes);
    writer.digest(binding.manifest_file_digest);
}

PackedRootRoleBinding decode_root_role(Reader &reader) {
    return PackedRootRoleBinding{
        reader.digest("root role semantic identity"),
        reader.digest("root role storage identity"),
        reader.u64("root role manifest bytes"),
        reader.digest("root role manifest digest")};
}

Bytes encode_root_manifest(const PackedRootManifest &manifest) {
    const Digest semantic = root_semantic_identity(manifest);
    const Digest storage = root_storage_identity(manifest, semantic);
    if (semantic != manifest.semantic_identity ||
        storage != manifest.storage_identity) {
        throw std::logic_error("inconsistent packed root-manifest identity");
    }
    Writer writer;
    writer.raw(kRootMagic);
    writer.u64(kPackedRootManifestVersion);
    writer.u64(0);
    writer.digest(manifest.workload.semantic_identity);
    writer.u64(manifest.workload.serialized_bytes);
    writer.digest(manifest.workload.file_digest);
    encode_root_role(writer, manifest.server);
    encode_root_role(writer, manifest.client);
    writer.digest(semantic);
    writer.digest(storage);
    writer.digest(domain_hash(kRootChecksumDomain, writer.view()));
    return std::move(writer).finish();
}

PackedRootManifest decode_root_manifest(
    std::span<const std::uint8_t> encoded,
    const std::filesystem::path &directory) {
    Reader reader(encoded);
    const auto magic = reader.take(kRootMagic.size(), "root-manifest magic");
    if (!std::equal(kRootMagic.begin(), kRootMagic.end(), magic.begin()) ||
        reader.u64("root-manifest version") !=
            kPackedRootManifestVersion ||
        reader.u64("root-manifest flags") != 0U) {
        throw std::invalid_argument("unsupported packed root manifest");
    }
    PackedRootManifest result;
    result.shared_directory = directory;
    result.workload.semantic_identity =
        reader.digest("root workload semantic identity");
    result.workload.serialized_bytes =
        reader.u64("root workload bytes");
    result.workload.file_digest =
        reader.digest("root workload file digest");
    result.server = decode_root_role(reader);
    result.client = decode_root_role(reader);
    result.semantic_identity = reader.digest("root semantic identity");
    result.storage_identity = reader.digest("root storage identity");
    const std::size_t checksum_offset = reader.position();
    const Digest checksum = reader.digest("root-manifest checksum");
    reader.finish();
    result.manifest_bytes = checked_u64(encoded.size(), "root manifest");
    if (result.semantic_identity != root_semantic_identity(result) ||
        result.storage_identity !=
            root_storage_identity(result, result.semantic_identity) ||
        checksum != domain_hash(kRootChecksumDomain,
                                encoded.first(checksum_offset)) ||
        !same_bytes(encode_root_manifest(result), encoded)) {
        throw std::invalid_argument(
            "packed root manifest is noncanonical or corrupted");
    }
    return result;
}

PackedPreprocessingOpenLimits open_limits(
    const PackedPreprocessingPublishLimits &limits) {
    return PackedPreprocessingOpenLimits{
        .max_workload_bytes = limits.max_workload_bytes,
        .max_role_artifact_bytes = limits.max_role_artifact_bytes,
        .max_manifest_bytes = limits.max_manifest_bytes,
        .max_artifact_tree_files = limits.max_artifact_tree_files,
        .max_artifact_tree_directories =
            limits.max_artifact_tree_directories,
        .max_artifact_tree_depth = limits.max_artifact_tree_depth,
        .max_artifact_tree_relative_path_bytes =
            limits.max_artifact_tree_relative_path_bytes,
        .max_artifact_tree_file_bytes =
            limits.max_artifact_tree_file_bytes,
        .max_artifact_tree_bytes = limits.max_artifact_tree_bytes,
        .workload_decode = limits.workload_decode};
}

void require_publish_limits(
    const PackedPreprocessingPublishLimits &limits) {
    if (limits.max_workload_bytes == 0 ||
        limits.max_role_artifact_bytes == 0 ||
        limits.max_manifest_bytes == 0 ||
        limits.max_artifact_tree_files == 0 ||
        limits.max_artifact_tree_directories == 0 ||
        limits.max_artifact_tree_depth == 0 ||
        limits.max_artifact_tree_relative_path_bytes == 0 ||
        limits.max_artifact_tree_file_bytes == 0 ||
        limits.max_artifact_tree_bytes == 0) {
        throw std::invalid_argument(
            "packed preprocessing publish limits are invalid");
    }
}

void require_open_limits(const PackedPreprocessingOpenLimits &limits) {
    if (limits.max_workload_bytes == 0 ||
        limits.max_role_artifact_bytes == 0 ||
        limits.max_manifest_bytes == 0 ||
        limits.max_artifact_tree_files == 0 ||
        limits.max_artifact_tree_directories == 0 ||
        limits.max_artifact_tree_depth == 0 ||
        limits.max_artifact_tree_relative_path_bytes == 0 ||
        limits.max_artifact_tree_file_bytes == 0 ||
        limits.max_artifact_tree_bytes == 0) {
        throw std::invalid_argument(
            "packed preprocessing open limits are invalid");
    }
}

PackedRootRoleBinding root_binding(const OpenedRoleInternal &role) {
    return PackedRootRoleBinding{
        role.manifest.semantic_identity, role.manifest.storage_identity,
        role.manifest.manifest_bytes, role.manifest_file_digest};
}

} // namespace

PackedStoredArtifact publish_packed_workload_static_file(
    const std::filesystem::path &shared_directory,
    const CertifiedPackedWorkloadStatic &workload,
    const PackedPreprocessingPublishLimits &limits) {
    require_publish_limits(limits);
    const std::filesystem::path directory =
        normalize_directory(shared_directory);
    require_entries(directory, {});
    const Bytes encoded = encode_packed_workload_static(workload);
    if (encoded.size() > limits.max_workload_bytes) {
        throw std::invalid_argument(
            "packed workload exceeds its publication limit");
    }
    const Digest file_digest = sha256(encoded);
    (void)decode_authenticated_packed_workload_static(
        encoded, file_digest, workload.semantic_identity(),
        limits.workload_decode);
    const std::filesystem::path workload_path =
        directory / std::string(kPackedWorkloadStaticFilename);
    bool published = false;
    try {
        publish_bytes(directory, kPackedWorkloadStaticFilename, encoded,
                      limits.min_free_bytes);
        published = true;
        require_entries(directory, {kPackedWorkloadStaticFilename});
    } catch (...) {
        if (published) {
            std::error_code ignored;
            std::filesystem::remove(workload_path, ignored);
        }
        throw;
    }
    return PackedStoredArtifact{
        checked_u64(encoded.size(), "packed workload"), file_digest,
        workload.semantic_identity()};
}

PackedRoleManifest publish_packed_role_manifest(
    const std::filesystem::path &role_directory,
    PackedPreprocessingRole role,
    const Digest &workload_semantic_identity,
    const Digest &role_artifact_semantic_identity,
    const Digest &artifact_tree_semantic_identity,
    const PackedPreprocessingPublishLimits &limits) {
    require_publish_limits(limits);
    if ((role != PackedPreprocessingRole::Server &&
        role != PackedPreprocessingRole::Client) ||
        is_zero(workload_semantic_identity) ||
        is_zero(role_artifact_semantic_identity) ||
        is_zero(artifact_tree_semantic_identity)) {
        throw std::invalid_argument(
            "packed role publication requires nonzero semantic identities");
    }
    const std::filesystem::path directory =
        normalize_directory(role_directory);
    require_entries(directory, {kPackedRoleStaticFilename,
                                kPackedRoleArtifactTreeDirectory});
    const std::filesystem::path artifact_path = fixed_file(
        directory, kPackedRoleStaticFilename, "packed role artifact");
    const InspectedFile inspected = inspect_file(
        artifact_path, limits.max_role_artifact_bytes,
        "packed role artifact");
    const std::filesystem::path tree_path = fixed_directory(
        directory, kPackedRoleArtifactTreeDirectory,
        "packed role artifact tree");
    PackedStoredArtifactTree inspected_tree = inspect_artifact_tree(
        tree_path, artifact_tree_semantic_identity,
        artifact_tree_limits(limits));
    PackedRoleManifest result;
    result.directory = directory;
    result.role = role;
    result.workload_semantic_identity = workload_semantic_identity;
    result.role_artifact = PackedStoredArtifact{
        inspected.serialized_bytes, inspected.digest,
        role_artifact_semantic_identity};
    result.artifact_tree = std::move(inspected_tree);
    result.semantic_identity = role_semantic_identity(
        role, workload_semantic_identity, role_artifact_semantic_identity,
        artifact_tree_semantic_identity);
    result.storage_identity =
        role_storage_identity(result.semantic_identity,
                              result.role_artifact,
                              result.artifact_tree);
    const std::uint64_t exact_manifest_bytes =
        role_manifest_encoded_bytes(result);
    if (exact_manifest_bytes > limits.max_manifest_bytes) {
        throw std::invalid_argument(
            "packed role manifest exceeds its publication limit");
    }
    const Bytes encoded = encode_role_manifest(result);
    if (checked_u64(encoded.size(), "role manifest") !=
        exact_manifest_bytes) {
        throw std::logic_error(
            "packed role manifest byte formula is inconsistent");
    }
    result.manifest_bytes = checked_u64(encoded.size(), "role manifest");
    const std::filesystem::path manifest_path =
        directory / std::string(kPackedManifestFilename);
    bool published = false;
    try {
        publish_bytes(directory, kPackedManifestFilename, encoded,
                      limits.min_free_bytes);
        published = true;
        require_entries(directory,
                        {kPackedRoleStaticFilename,
                         kPackedRoleArtifactTreeDirectory,
                         kPackedManifestFilename});
    } catch (...) {
        if (published) {
            std::error_code ignored;
            std::filesystem::remove(manifest_path, ignored);
        }
        throw;
    }
    return result;
}

PackedRootManifest publish_packed_preprocessing_root(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const std::filesystem::path &client_directory,
    const CertifiedPackedWorkloadStatic &expected_workload,
    const PackedPreprocessingPublishLimits &limits) {
    require_publish_limits(limits);
    const std::filesystem::path shared =
        normalize_directory(shared_directory);
    const std::filesystem::path server =
        normalize_directory(server_directory);
    const std::filesystem::path client =
        normalize_directory(client_directory);
    if (directories_overlap(shared, server) ||
        directories_overlap(shared, client) ||
        directories_overlap(server, client)) {
        throw std::invalid_argument(
            "packed preprocessing role directories must be disjoint");
    }
    require_entries(shared, {kPackedWorkloadStaticFilename});
    const std::filesystem::path workload_path = fixed_file(
        shared, kPackedWorkloadStaticFilename, "packed workload");
    const Bytes workload_bytes = read_file(
        workload_path, limits.max_workload_bytes, "packed workload");
    const Bytes expected_bytes =
        encode_packed_workload_static(expected_workload);
    if (!same_bytes(expected_bytes, workload_bytes)) {
        throw std::invalid_argument(
            "published workload differs from certified setup ownership");
    }
    const Digest workload_file_digest = sha256(workload_bytes);
    (void)decode_authenticated_packed_workload_static(
        workload_bytes, workload_file_digest,
        expected_workload.semantic_identity(), limits.workload_decode);

    const PackedPreprocessingOpenLimits opening = open_limits(limits);
    const OpenedRoleInternal opened_server = open_role_internal(
        server, PackedPreprocessingRole::Server,
        expected_workload.semantic_identity(), nullptr, opening);
    const OpenedRoleInternal opened_client = open_role_internal(
        client, PackedPreprocessingRole::Client,
        expected_workload.semantic_identity(), nullptr, opening);

    PackedRootManifest result;
    result.shared_directory = shared;
    result.workload = PackedStoredArtifact{
        checked_u64(workload_bytes.size(), "packed workload"),
        workload_file_digest, expected_workload.semantic_identity()};
    result.server = root_binding(opened_server);
    result.client = root_binding(opened_client);
    result.semantic_identity = root_semantic_identity(result);
    result.storage_identity =
        root_storage_identity(result, result.semantic_identity);
    const Bytes encoded = encode_root_manifest(result);
    if (encoded.size() > limits.max_manifest_bytes) {
        throw std::invalid_argument(
            "packed root manifest exceeds its publication limit");
    }
    result.manifest_bytes = checked_u64(encoded.size(), "root manifest");
    const std::filesystem::path manifest_path =
        shared / std::string(kPackedManifestFilename);
    bool published = false;
    try {
        publish_bytes(shared, kPackedManifestFilename, encoded,
                      limits.min_free_bytes);
        published = true;
        require_entries(shared,
                        {kPackedWorkloadStaticFilename,
                         kPackedManifestFilename});
    } catch (...) {
        if (published) {
            std::error_code ignored;
            std::filesystem::remove(manifest_path, ignored);
        }
        throw;
    }
    return result;
}

OpenedPackedRootPreprocessing open_packed_preprocessing_root(
    const std::filesystem::path &shared_directory,
    const Digest &expected_root_storage_identity,
    const PackedPreprocessingOpenLimits &limits) {
    require_open_limits(limits);
    if (is_zero(expected_root_storage_identity)) {
        throw std::invalid_argument(
            "packed root storage identity must be authenticated");
    }
    const std::filesystem::path shared =
        normalize_directory(shared_directory);
    require_entries(shared,
                    {kPackedWorkloadStaticFilename,
                     kPackedManifestFilename});
    const std::filesystem::path manifest_path = fixed_file(
        shared, kPackedManifestFilename, "packed root manifest");
    const Bytes encoded = read_file(manifest_path,
                                    limits.max_manifest_bytes,
                                    "packed root manifest");
    PackedRootManifest manifest = decode_root_manifest(encoded, shared);
    if (manifest.storage_identity != expected_root_storage_identity) {
        throw std::invalid_argument(
            "packed root has the wrong authenticated storage identity");
    }
    const std::filesystem::path workload_path = fixed_file(
        shared, kPackedWorkloadStaticFilename, "packed workload");
    const Bytes workload_bytes = read_file(
        workload_path, limits.max_workload_bytes, "packed workload");
    if (checked_u64(workload_bytes.size(), "packed workload") !=
            manifest.workload.serialized_bytes ||
        sha256(workload_bytes) != manifest.workload.file_digest) {
        throw std::invalid_argument(
            "packed workload differs from its root manifest");
    }
    CertifiedPackedWorkloadStatic workload =
        decode_authenticated_packed_workload_static(
            workload_bytes, manifest.workload.file_digest,
            manifest.workload.semantic_identity,
            limits.workload_decode);
    return OpenedPackedRootPreprocessing{std::move(manifest),
                                         std::move(workload)};
}

namespace {

OpenedPackedRolePreprocessing open_packed_role_preprocessing(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &role_directory,
    PackedPreprocessingRole role,
    const Digest &expected_root_storage_identity,
    const PackedPreprocessingOpenLimits &limits) {
    const std::filesystem::path normalized_shared =
        normalize_directory(shared_directory);
    const std::filesystem::path normalized_role =
        normalize_directory(role_directory);
    if (directories_overlap(normalized_shared, normalized_role)) {
        throw std::invalid_argument(
            "packed role and shared directories must be disjoint");
    }
    OpenedPackedRootPreprocessing opened_root =
        open_packed_preprocessing_root(
            normalized_shared, expected_root_storage_identity, limits);
    const PackedRootRoleBinding &binding =
        role == PackedPreprocessingRole::Server
            ? opened_root.manifest.server
            : opened_root.manifest.client;
    OpenedRoleInternal opened_role = open_role_internal(
        normalized_role, role,
        opened_root.manifest.workload.semantic_identity,
        &binding, limits);
    return OpenedPackedRolePreprocessing{
        std::move(opened_root.manifest),
        std::move(opened_role.manifest),
        std::move(opened_root.workload),
        std::move(opened_role.artifact_path),
        std::move(opened_role.artifact_tree_path)};
}

} // namespace

OpenedPackedRolePreprocessing open_packed_server_preprocessing(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const Digest &expected_root_storage_identity,
    const PackedPreprocessingOpenLimits &limits) {
    return open_packed_role_preprocessing(
        shared_directory, server_directory,
        PackedPreprocessingRole::Server,
        expected_root_storage_identity, limits);
}

OpenedPackedRolePreprocessing open_packed_client_preprocessing(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &client_directory,
    const Digest &expected_root_storage_identity,
    const PackedPreprocessingOpenLimits &limits) {
    return open_packed_role_preprocessing(
        shared_directory, client_directory,
        PackedPreprocessingRole::Client,
        expected_root_storage_identity, limits);
}

} // namespace laminate::protocol
