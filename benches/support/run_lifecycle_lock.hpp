#ifndef LAMINATE_BENCHES_RUN_LIFECYCLE_LOCK_HPP
#define LAMINATE_BENCHES_RUN_LIFECYCLE_LOCK_HPP

/// @file run_lifecycle_lock.hpp
/// @brief Coordinate benchmark roles, report readers, and run cleanup.

#include <cerrno>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace laminate::bench {

enum class RunLifecycleLockMode {
    Shared,
    Exclusive,
};

/// Holds an advisory lock on RUN/shared/lifecycle.lock.
///
/// Setup and every process that reads or writes a run hold a shared lock.
/// Cleanup holds each deletion candidate exclusively, so no new role or
/// report reader can enter while that directory is renamed and removed.
class RunLifecycleLock {
  public:
    RunLifecycleLock(const std::filesystem::path &run_directory,
                     RunLifecycleLockMode mode) {
        require_private_directory(run_directory, "benchmark run");
        require_private_directory(run_directory / "shared",
                                  "benchmark shared directory");
        const std::filesystem::path path =
            run_directory / "shared" / "lifecycle.lock";
        int flags = O_RDWR | O_CREAT | O_CLOEXEC | O_NONBLOCK;
#if defined(O_NOFOLLOW)
        flags |= O_NOFOLLOW;
#endif
        descriptor_ = ::open(path.c_str(), flags, S_IRUSR | S_IWUSR);
        if (descriptor_ < 0) {
            throw std::system_error(
                errno, std::generic_category(),
                "cannot open benchmark run lifecycle lock " +
                    path.string());
        }
        try {
            struct stat metadata {};
            if (::fstat(descriptor_, &metadata) != 0) {
                throw std::system_error(
                    errno, std::generic_category(),
                    "cannot inspect benchmark run lifecycle lock " +
                        path.string());
            }
            if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
                (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
                throw std::invalid_argument(
                    "benchmark run lifecycle lock must be an owner-only "
                    "regular file: " +
                    path.string());
            }
            const int operation =
                (mode == RunLifecycleLockMode::Shared ? LOCK_SH : LOCK_EX) |
                LOCK_NB;
            if (::flock(descriptor_, operation) != 0) {
                const int saved_errno = errno;
                if (saved_errno == EWOULDBLOCK || saved_errno == EAGAIN) {
                    throw std::runtime_error(
                        mode == RunLifecycleLockMode::Shared
                            ? "benchmark run is being cleaned up: " +
                                  run_directory.string()
                            : "benchmark run is active: " +
                                  run_directory.string());
                }
                throw std::system_error(
                    saved_errno, std::generic_category(),
                    "cannot lock benchmark run lifecycle file " +
                        path.string());
            }
        } catch (...) {
            ::close(descriptor_);
            descriptor_ = -1;
            throw;
        }
    }

    RunLifecycleLock(const RunLifecycleLock &) = delete;
    RunLifecycleLock &operator=(const RunLifecycleLock &) = delete;

    RunLifecycleLock(RunLifecycleLock &&other) noexcept
        : descriptor_(other.descriptor_) {
        other.descriptor_ = -1;
    }

    RunLifecycleLock &operator=(RunLifecycleLock &&other) noexcept {
        if (this == &other) {
            return *this;
        }
        release();
        descriptor_ = other.descriptor_;
        other.descriptor_ = -1;
        return *this;
    }

    ~RunLifecycleLock() { release(); }

  private:
    static void require_private_directory(
        const std::filesystem::path &path, const char *description) {
        struct stat metadata {};
        if (::lstat(path.c_str(), &metadata) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    std::string("cannot inspect ") +
                                        description + " " + path.string());
        }
        if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
            (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            throw std::invalid_argument(
                std::string(description) +
                " must be an owner-controlled real directory: " +
                path.string());
        }
    }

    void release() noexcept {
        if (descriptor_ < 0) {
            return;
        }
        (void)::flock(descriptor_, LOCK_UN);
        (void)::close(descriptor_);
        descriptor_ = -1;
    }

    int descriptor_ = -1;
};

} // namespace laminate::bench

#endif // LAMINATE_BENCHES_RUN_LIFECYCLE_LOCK_HPP
