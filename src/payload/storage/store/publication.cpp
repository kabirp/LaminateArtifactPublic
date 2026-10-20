/// @file publication.cpp
/// @brief Exclusive staging and atomic no-replace publication.

#include "../format/layer_format.hpp"

#include <optional>

namespace laminate::payload {
namespace trace_store_format {

FileIdentity write_exclusive_partial(const std::filesystem::path &path,
                                     std::span<const std::uint8_t> bytes,
                                     const char *description,
                                     FileIoReport *io_report) {
    std::optional<FileIdentity> owned;
    std::shared_ptr<ExclusiveOutputFile> output;
    try {
        output = create_exclusive_output_file(path, description);
        owned = output->identity(path, description);
        write_exact(*output, bytes, description);
        const FileIdentity completed =
            output->identity(path, description);
        output->close(description);
        if (io_report != nullptr) {
            *io_report = output->io_report();
        }
        return completed;
    } catch (...) {
        if (owned && output && output->is_open()) {
            try {
                owned = output->identity(path, description);
            } catch (...) {
            }
            try {
                output->close(description);
            } catch (...) {
            }
        }
        if (owned) {
            remove_owned_file_noexcept(path, *owned);
        }
        throw;
    }
}

void write_new_published_file(const std::filesystem::path &partial,
                              const std::filesystem::path &final,
                              std::span<const std::uint8_t> bytes,
                              const char *description) {
    const FileIdentity identity =
        write_exclusive_partial(partial, bytes, description);
    try {
        publish_file_no_replace(partial, final, identity, description);
    } catch (...) {
        remove_owned_file_noexcept(partial, identity);
        throw;
    }
}

} // namespace trace_store_format
} // namespace laminate::payload
