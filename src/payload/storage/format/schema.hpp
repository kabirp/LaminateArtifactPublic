#ifndef LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_SCHEMA_HPP
#define LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_SCHEMA_HPP

/// @file schema.hpp
/// @brief Private v4 constants, path rules, and descriptor primitives.

#include "laminate/payload/storage/file_trace_store.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

namespace laminate::payload::trace_store_format {

inline constexpr std::uint64_t kFormatVersion = 4;
inline constexpr std::uint64_t kMaximumManifestBytes = 64ULL << 20U;
inline constexpr std::uint64_t kMaximumRecordBytes = 1ULL << 30U;
inline constexpr std::size_t kMaximumTraceLayers = 1ULL << 16U;
inline constexpr std::size_t kMaximumRecordsPerLayer = 1ULL << 20U;
inline constexpr std::uint64_t kLayerHeaderBytes =
    5 * sizeof(std::uint64_t);
inline constexpr std::uint64_t kIndexHeaderBytes =
    3 * sizeof(std::uint64_t);
inline constexpr std::uint64_t kManifestFixedBytes =
    8 + 5 * sizeof(std::uint64_t) + 3 * Digest{}.size() +
    3 * sizeof(std::uint64_t) + Digest{}.size();
inline constexpr std::uint64_t kLayerManifestBytes =
    8 * sizeof(std::uint64_t) + Digest{}.size();
inline constexpr std::uint64_t kMinimumRecordAndIndexBytes =
    2 * sizeof(std::uint64_t) + 1;

inline constexpr std::array<std::uint8_t, 8> kManifestMagic{
    'L', 'A', 'M', 'T', 'R', 'C', '0', '4'};
inline constexpr std::array<std::uint8_t, 8> kLayerMagic{
    'L', 'A', 'M', 'L', 'Y', 'R', '0', '4'};
inline constexpr std::array<std::uint8_t, 8> kIndexMagic{
    'L', 'A', 'M', 'I', 'D', 'X', '0', '4'};
inline constexpr std::array<std::uint8_t, 8> kRetirementSessionMagic{
    'L', 'A', 'M', 'R', 'T', 'S', '0', '4'};
inline constexpr std::array<std::uint8_t, 8> kRetirementEventMagic{
    'L', 'A', 'M', 'R', 'T', 'E', '0', '4'};
inline constexpr std::uint64_t kRetirementSessionBytes =
    8 + 3 * sizeof(std::uint64_t) + 5 * Digest{}.size();
inline constexpr std::uint64_t kRetirementEventBytes =
    8 + 5 * sizeof(std::uint64_t) + 3 * Digest{}.size();

std::uint64_t checked_u64(std::size_t value, const char *what);
std::size_t checked_size(std::uint64_t value, const char *what);
std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *what);
std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               const char *what);
std::uint64_t manifest_encoded_bytes(std::size_t layer_count);
void validate_dimensions(const LayerDimensions &dimensions);
void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value);
void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &digest);
void append_magic(std::vector<std::uint8_t> &output,
                  const std::array<std::uint8_t, 8> &magic);
std::uint64_t layout_code(TraceLayerLayout layout);
TraceLayerLayout parse_layout(std::uint64_t code);
std::uint64_t shape_code(PayloadKind kind);
PayloadKind parse_shape(std::uint64_t code);
std::uint64_t provenance_code(TraceProvenance provenance);
TraceProvenance parse_provenance(std::uint64_t code);

/// Sequential decoder for the fixed-width v4 metadata records.
class ByteReader {
  public:
    explicit ByteReader(std::span<const std::uint8_t> bytes);

    std::uint64_t u64(const char *description);
    Digest digest(const char *description);
    void magic(const std::array<std::uint8_t, 8> &expected,
               const char *description);
    std::size_t position() const;

  private:
    void require(std::size_t count, const char *description) const;

    std::span<const std::uint8_t> bytes_;
    std::size_t position_ = 0;
};

std::filesystem::path layer_path(const std::filesystem::path &directory,
                                 std::size_t layer_index,
                                 std::string_view suffix);
std::filesystem::path manifest_path(
    const std::filesystem::path &directory);
std::filesystem::path partial_manifest_path(
    const std::filesystem::path &directory);
std::filesystem::path retirement_session_path(
    const std::filesystem::path &directory);
std::filesystem::path retirement_event_path(
    const std::filesystem::path &directory, std::uint64_t generation,
    std::string_view suffix);

struct LayerFileSummary {
    std::uint64_t file_size = 0;
    Digest digest{};
};

} // namespace laminate::payload::trace_store_format

#endif // LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_SCHEMA_HPP
