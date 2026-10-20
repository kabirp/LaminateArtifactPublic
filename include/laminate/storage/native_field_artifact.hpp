#ifndef LAMINATE_STORAGE_NATIVE_FIELD_ARTIFACT_HPP
#define LAMINATE_STORAGE_NATIVE_FIELD_ARTIFACT_HPP

/// @file native_field_artifact.hpp
/// @brief Versioned, bounded storage for BaseFold-sized native-field arrays.

#include "laminate/basefold/digest.hpp"
#include "laminate/field/fq.hpp"
#include "laminate/field/fq2.hpp"
#include "laminate/transcript/hash.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace laminate::storage {

/// Canonical fixed-width element encodings supported by the v1 format.
enum class NativeFieldElementKind : std::uint64_t {
    Fq = 1,
    Fq2 = 2,
    BaseFoldDigest = 3,
};

std::size_t encoded_element_bytes(NativeFieldElementKind kind);

/// Array declaration used to obtain the exact physical size of a completed
/// v1 artifact before creating any files.
struct NativeFieldArrayLayout {
    std::string name;
    NativeFieldElementKind kind = NativeFieldElementKind::Fq;
    std::uint64_t element_count = 0;
};

/// Checked exact byte count for the array files and manifest that the v1
/// writer will publish. The same names, counts, and format limits as the
/// writer are enforced.
std::uint64_t native_field_artifact_physical_bytes(
    std::span<const NativeFieldArrayLayout> arrays);

/// Mandatory limits for creating one artifact. `max_total_bytes` includes
/// array headers, payloads, and the manifest. `min_free_bytes` is the disk
/// space that must remain after each reservation.
struct NativeFieldArtifactOptions {
    std::uint64_t max_total_bytes = 0;
    std::uint64_t min_free_bytes = 0;
};

struct NativeFieldArrayDescriptor {
    std::string name;
    NativeFieldElementKind kind = NativeFieldElementKind::Fq;
    std::uint64_t element_count = 0;
    std::uint64_t encoded_element_bytes = 0;
    std::uint64_t physical_bytes = 0;
    Digest file_digest{};

    bool operator==(const NativeFieldArrayDescriptor &other) const = default;
};

struct NativeFieldArtifactWriteResult {
    std::filesystem::path directory;
    Digest identity{};
    std::vector<NativeFieldArrayDescriptor> arrays;
    std::uint64_t physical_bytes = 0;
    /// Extra full-file reads needed to hash arrays written out of order.
    std::uint64_t positional_publication_read_bytes = 0;
    std::uint64_t positional_publication_read_operations = 0;
};

class NativeFieldArtifact;

/// Incremental writer for one artifact. The destination must be an existing,
/// empty, caller-owned private directory; this component never chooses a
/// temporary or repository-relative path. Array files are renamed from
/// `.partial` names as they finish, and the manifest is published only after
/// all declared data is complete. This ordering detects incomplete stores but
/// does not promise fsync-level power-loss durability.
class NativeFieldArtifactWriter {
  public:
    NativeFieldArtifactWriter(std::filesystem::path directory,
                              NativeFieldArtifactOptions options,
                              Digest identity);
    ~NativeFieldArtifactWriter();

    NativeFieldArtifactWriter(const NativeFieldArtifactWriter &) = delete;
    NativeFieldArtifactWriter &
    operator=(const NativeFieldArtifactWriter &) = delete;
    NativeFieldArtifactWriter(NativeFieldArtifactWriter &&) noexcept;
    NativeFieldArtifactWriter &
    operator=(NativeFieldArtifactWriter &&) noexcept;

    void begin_array(std::string name, NativeFieldElementKind kind,
                     std::uint64_t element_count);
    /// Start an Fq array whose disjoint ranges will be written out of order.
    /// The caller must cover every element exactly once before finishing.
    /// Publication rereads the complete file for its digest and emits the
    /// standard manifest-last v1 representation, which ordinary artifact
    /// opening then validates normally.
    void begin_positional_fq_array(std::string name,
                                   std::uint64_t element_count);
    void append(std::span<const Fq> values);
    void append(std::span<const Fq2> values);
    void append(std::span<const basefold::Digest> values);
    void write_fq_at(std::uint64_t element_index,
                     std::span<const Fq> values);
    void finish_array();
    NativeFieldArtifactWriteResult finish();

    /// Return the immutable artifact just published by this writer without
    /// rereading every payload byte. This is a trusted in-process transition:
    /// it is available only after `finish()` and is intended for a private
    /// directory that has remained unchanged since publication. Persisted or
    /// externally supplied artifacts must still enter through
    /// `NativeFieldArtifact::open`, which performs the complete fail-closed
    /// integrity and canonical-encoding scan.
    NativeFieldArtifact trusted_finished_artifact() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Independent, bounded-memory reader for one typed array. Reads and seeks
/// are expressed in elements rather than bytes.
class NativeFieldArrayReader {
  public:
    ~NativeFieldArrayReader();

    NativeFieldArrayReader(const NativeFieldArrayReader &) = delete;
    NativeFieldArrayReader &operator=(const NativeFieldArrayReader &) =
        delete;
    NativeFieldArrayReader(NativeFieldArrayReader &&) noexcept;
    NativeFieldArrayReader &
    operator=(NativeFieldArrayReader &&) noexcept;

    NativeFieldElementKind kind() const;
    std::uint64_t size() const;
    std::uint64_t position() const;
    void seek(std::uint64_t element_index);
    void rewind();
    std::size_t read(std::span<Fq> output);
    std::size_t read(std::span<Fq2> output);
    std::size_t read(std::span<basefold::Digest> output);

  private:
    struct Impl;
    explicit NativeFieldArrayReader(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;

    friend class NativeFieldArtifact;
};

/// Validated artifact metadata. Opening makes one sequential integrity and
/// canonical-encoding pass over every array while retaining only a small I/O
/// buffer. The caller must keep the directory private and unchanged while the
/// artifact or its readers are in use.
class NativeFieldArtifact {
  public:
    static NativeFieldArtifact open(
        const std::filesystem::path &directory,
        const Digest &expected_identity);

    const std::filesystem::path &directory() const;
    const Digest &identity() const;
    const std::vector<NativeFieldArrayDescriptor> &arrays() const;
    std::uint64_t physical_bytes() const;
    const NativeFieldArrayDescriptor &array(std::string_view name) const;
    NativeFieldArrayReader open_array(std::string_view name) const;

  private:
    struct Impl;
    explicit NativeFieldArtifact(std::shared_ptr<const Impl> impl);
    std::shared_ptr<const Impl> impl_;

    friend class NativeFieldArtifactWriter;
};

} // namespace laminate::storage

#endif // LAMINATE_STORAGE_NATIVE_FIELD_ARTIFACT_HPP
