#ifndef LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_LAYER_FORMAT_HPP
#define LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_LAYER_FORMAT_HPP

/// @file layer_format.hpp
/// @brief Private layer-record framing and digest contract.

#include "files.hpp"
#include "schema.hpp"

namespace laminate::payload::trace_store_format {

Digest initial_layer_digest(std::size_t layer_index,
                            std::size_t record_count);
Digest extend_layer_digest(const Digest &previous,
                           std::size_t record_index,
                           std::size_t record_length,
                           const Digest &record_digest);
void write_exact(ExclusiveOutputFile &output,
                 std::span<const std::uint8_t> bytes,
                 const char *description);
void write_u64(ExclusiveOutputFile &output, std::uint64_t value,
               const char *description);
void write_u64_at(ExclusiveOutputFile &output, std::uint64_t offset,
                  std::uint64_t value, const char *description);
void read_exact(BoundInputFile &input,
                std::span<std::uint8_t> output,
                const char *description);
std::uint64_t read_u64(BoundInputFile &input,
                       const char *description);
std::uint64_t stream_position(const BoundInputFile &input,
                              const char *description);
std::uint64_t stream_position(const ExclusiveOutputFile &output,
                              const char *description);

} // namespace laminate::payload::trace_store_format

#endif // LAMINATE_PAYLOAD_STORAGE_TRACE_STORE_LAYER_FORMAT_HPP
