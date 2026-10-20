#ifndef LAMINATE_BENCHES_COMPLETED_RESULT_REPORT_HPP
#define LAMINATE_BENCHES_COMPLETED_RESULT_REPORT_HPP

/// @file completed_result_report.hpp
/// @brief Publish benchmark records only after successful completion.

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace laminate::bench {

/// Mirrors a benchmark record in memory and publishes its owner-only artifact
/// only after the caller reports success. On POSIX, publication writes and
/// flushes a same-directory temporary inode before atomically linking it at
/// the final no-replace path, so an interrupted POSIX run cannot leave a
/// partial file that looks like a completed result.
class CompletedResultReport {
  public:
    explicit CompletedResultReport(std::filesystem::path path)
        : path_(std::move(path)) {
        if (path_.empty()) {
            return;
        }
        std::error_code error;
        std::filesystem::file_status destination =
            std::filesystem::symlink_status(path_, error);
        if (error == std::errc::no_such_file_or_directory) {
            error.clear();
            destination = std::filesystem::file_status(
                std::filesystem::file_type::not_found);
        } else if (error) {
            throw std::runtime_error(
                "cannot inspect --result-file destination: " +
                error.message());
        }
        if (destination.type() != std::filesystem::file_type::not_found) {
            throw std::invalid_argument(
                "--result-file must not already exist");
        }

        const std::filesystem::path parent =
            path_.parent_path().empty() ? std::filesystem::path(".")
                                        : path_.parent_path();
        const std::filesystem::file_status parent_status =
            std::filesystem::status(parent, error);
        if (error || !std::filesystem::is_directory(parent_status)) {
            throw std::invalid_argument(
                "--result-file parent must be an existing directory");
        }
    }

    std::ostream *mirror() noexcept {
        return path_.empty() ? nullptr : &buffer_;
    }

    void publish() {
        if (path_.empty()) {
            return;
        }
        const std::string report = buffer_.str();
        if (report.empty()) {
            throw std::logic_error(
                "cannot publish an empty benchmark report");
        }
#ifndef _WIN32
        const std::filesystem::path parent =
            path_.parent_path().empty() ? std::filesystem::path(".")
                                        : path_.parent_path();
        std::string temporary_pattern =
            (parent / ".laminate-result-XXXXXX").string();
        std::vector<char> temporary_buffer(temporary_pattern.begin(),
                                           temporary_pattern.end());
        temporary_buffer.push_back('\0');
        int descriptor = ::mkstemp(temporary_buffer.data());
        if (descriptor < 0) {
            throw std::system_error(
                errno, std::generic_category(),
                "failed to create temporary --result-file");
        }
        const std::filesystem::path temporary_path(temporary_buffer.data());
        bool final_path_linked = false;
        try {
            std::size_t written = 0;
            while (written != report.size()) {
                const ssize_t count = ::write(
                    descriptor, report.data() + written,
                    report.size() - written);
                if (count < 0 && errno == EINTR) {
                    continue;
                }
                if (count <= 0) {
                    throw std::system_error(
                        count < 0 ? errno : EIO, std::generic_category(),
                        "failed to write --result-file");
                }
                written += static_cast<std::size_t>(count);
            }
            if (::fsync(descriptor) != 0) {
                throw std::system_error(
                    errno, std::generic_category(),
                    "failed to flush --result-file to disk");
            }
            if (::close(descriptor) != 0) {
                descriptor = -1;
                throw std::system_error(
                    errno, std::generic_category(),
                    "failed to close --result-file");
            }
            descriptor = -1;

            if (::link(temporary_path.c_str(), path_.c_str()) != 0) {
                throw std::system_error(
                    errno, std::generic_category(),
                    "failed to publish --result-file without replacing an "
                    "existing artifact");
            }
            final_path_linked = true;
            if (::unlink(temporary_path.c_str()) != 0) {
                throw std::system_error(
                    errno, std::generic_category(),
                    "failed to remove temporary --result-file link");
            }

            const int directory = ::open(parent.c_str(), O_RDONLY);
            if (directory < 0) {
                throw std::system_error(
                    errno, std::generic_category(),
                    "failed to open --result-file parent directory");
            }
            if (::fsync(directory) != 0) {
                const int saved_errno = errno;
                ::close(directory);
                throw std::system_error(
                    saved_errno, std::generic_category(),
                    "failed to flush --result-file parent directory");
            }
            if (::close(directory) != 0) {
                throw std::system_error(
                    errno, std::generic_category(),
                    "failed to close --result-file parent directory");
            }
        } catch (...) {
            if (descriptor >= 0) {
                ::close(descriptor);
            }
            std::error_code ignored;
            std::filesystem::remove(temporary_path, ignored);
            if (final_path_linked) {
                std::filesystem::remove(path_, ignored);
            }
            throw;
        }
#else
        std::ofstream output(path_, std::ios::binary | std::ios::out);
        if (!output) {
            throw std::runtime_error("failed to create --result-file");
        }
        output.write(report.data(), static_cast<std::streamsize>(report.size()));
        output.flush();
        if (!output) {
            output.close();
            std::error_code ignored;
            std::filesystem::remove(path_, ignored);
            throw std::runtime_error("failed to write --result-file");
        }
        output.close();
#endif
    }

  private:
    std::filesystem::path path_;
    std::ostringstream buffer_;
};

} // namespace laminate::bench

#endif // LAMINATE_BENCHES_COMPLETED_RESULT_REPORT_HPP
