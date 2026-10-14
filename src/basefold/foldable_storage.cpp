#include "laminate/basefold/foldable_storage.hpp"
#include "laminate/field/serialization.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>

namespace laminate::basefold::foldable {
struct ScalarArray::Impl {
    std::filesystem::path path;
    std::size_t count = 0;
    int fd = -1;
    bool remove = true;
    bool writable = true;
    ~Impl() {
        if (fd >= 0)
            ::close(fd);
        if (remove && fd >= 0) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    }
};
namespace {
[[noreturn]] void io_error(const char *what) {
    throw std::system_error(errno, std::generic_category(), what);
}
void transfer(int fd, std::size_t offset, std::span<std::uint8_t> bytes,
              bool write) {
    std::size_t done = 0;
    while (done < bytes.size()) {
        const auto result =
            write ? ::pwrite(fd, bytes.data() + done, bytes.size() - done,
                             static_cast<off_t>(offset + done))
                  : ::pread(fd, bytes.data() + done, bytes.size() - done,
                            static_cast<off_t>(offset + done));
        if (result < 0) {
            if (errno == EINTR)
                continue;
            io_error("foldable field file I/O");
        }
        if (result == 0)
            throw std::runtime_error("truncated foldable field file");
        done += static_cast<std::size_t>(result);
    }
}
void check_range(std::size_t size, std::size_t offset, std::size_t count) {
    if (offset > size || count > size - offset)
        throw std::out_of_range("foldable field array range");
}
}
ScalarArray ScalarArray::create(const std::filesystem::path &path,
                                std::size_t count) {
    if (count > static_cast<std::size_t>(std::numeric_limits<off_t>::max()) /
                    kSerializedFpkBytes)
        throw std::length_error(
            "foldable field file exceeds positional I/O range");
    auto impl = std::make_shared<Impl>();
    impl->path = path;
    impl->count = count;
    impl->fd = ::open(path.c_str(),
                      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (impl->fd < 0)
        io_error("create exclusive foldable field file");
    if (::ftruncate(impl->fd,
                    static_cast<off_t>(count * kSerializedFpkBytes)) != 0)
        io_error("size foldable field file");
    return ScalarArray(std::move(impl));
}
ScalarArray ScalarArray::open_read_only_at(
    int directory_fd, const std::filesystem::path &directory,
    const std::string &name, std::size_t count) {
    if (name.empty() || name == "." || name == ".." ||
        name.find('/') != std::string::npos ||
        count > static_cast<std::size_t>(std::numeric_limits<off_t>::max()) /
                    kSerializedFpkBytes)
        throw std::invalid_argument("foldable: invalid persisted field geometry");
    auto impl = std::make_shared<Impl>();
    impl->path = directory / name;
    impl->count = count;
    impl->remove = false;
    impl->writable = false;
    impl->fd = ::openat(directory_fd, name.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (impl->fd < 0)
        io_error("open persisted foldable field file");
    struct stat status{};
    if (::fstat(impl->fd, &status) != 0)
        io_error("stat persisted foldable field file");
    if (!S_ISREG(status.st_mode) || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) !=
            count * kSerializedFpkBytes)
        throw std::invalid_argument("foldable: persisted field file size/type");
    return ScalarArray(std::move(impl));
}
ScalarArray ScalarArray::open_read_only(const std::filesystem::path &path,
                                      std::size_t count) {
    const auto parent = path.parent_path().empty()
                            ? std::filesystem::path(".") : path.parent_path();
    const int directory = ::open(parent.c_str(),
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (directory < 0)
        io_error("open persisted foldable field directory");
    try {
        auto result = open_read_only_at(directory, parent,
                                        path.filename().string(), count);
        ::close(directory);
        return result;
    } catch (...) {
        ::close(directory);
        throw;
    }
}
std::size_t ScalarArray::size() const { return impl_ ? impl_->count : 0; }
void ScalarArray::read_block(std::size_t offset, std::span<Fpk> values) const {
    if (!impl_)
        throw std::logic_error("empty foldable field array");
    check_range(size(), offset, values.size());
    // The conversion buffer is bounded independently of the caller's span.
    std::array<std::uint8_t, 4096 * kSerializedFpkBytes> bytes;
    for (std::size_t start = 0; start < values.size(); start += 4096) {
        const auto count = std::min<std::size_t>(4096, values.size() - start);
        transfer(impl_->fd, (offset + start) * kSerializedFpkBytes,
                 std::span(bytes).first(count * kSerializedFpkBytes), false);
        for (std::size_t i = 0; i < count; ++i)
            values[start + i] = deserialize_fpk(std::span(bytes).subspan(
                i * kSerializedFpkBytes, kSerializedFpkBytes));
    }
}
void ScalarArray::write_block(std::size_t offset, std::span<const Fpk> values) {
    if (impl_ && !impl_->writable)
        throw std::logic_error("read-only foldable field array");
    if (!impl_)
        throw std::logic_error("empty foldable field array");
    check_range(size(), offset, values.size());
    std::array<std::uint8_t, 4096 * kSerializedFpkBytes> bytes;
    for (std::size_t start = 0; start < values.size(); start += 4096) {
        const auto count = std::min<std::size_t>(4096, values.size() - start);
        for (std::size_t i = 0; i < count; ++i) {
            const auto encoded = serialize(values[start + i]);
            std::copy(encoded.begin(), encoded.end(),
                      bytes.begin() +
                          static_cast<std::ptrdiff_t>(i * kSerializedFpkBytes));
        }
        transfer(impl_->fd, (offset + start) * kSerializedFpkBytes,
                 std::span(bytes).first(count * kSerializedFpkBytes), true);
    }
}
Fpk ScalarArray::get(std::size_t offset) const {
    Fpk result;
    read_block(offset, std::span(&result, 1));
    return result;
}
void ScalarArray::set(std::size_t offset, const Fpk &value) {
    write_block(offset, std::span(&value, 1));
}
void ScalarArray::retain() {
    if (!impl_)
        throw std::logic_error("empty foldable field array");
    impl_->remove = false;
}
const std::filesystem::path &ScalarArray::path() const {
    if (!impl_)
        throw std::logic_error("empty foldable field array");
    return impl_->path;
}
ValueSource source(const ScalarArray &array) {
    return {array.size(), [array](std::size_t offset, std::span<Fpk> out) {
                array.read_block(offset, out);
            }};
}
ValueSource source(std::span<const Fpk> values) {
    return {values.size(), [values](std::size_t offset, std::span<Fpk> out) {
                check_range(values.size(), offset, out.size());
                std::copy_n(values.begin() +
                                static_cast<std::ptrdiff_t>(offset),
                            out.size(), out.begin());
            }};
}
} // namespace laminate::basefold::foldable
