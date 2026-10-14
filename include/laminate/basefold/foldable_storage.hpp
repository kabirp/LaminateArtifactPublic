#ifndef LAMINATE_BASEFOLD_FOLDABLE_STORAGE_HPP
#define LAMINATE_BASEFOLD_FOLDABLE_STORAGE_HPP

#include "laminate/field/fpk.hpp"
#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>

namespace laminate::basefold::foldable {

struct Commitment;
struct Metadata;

/// Bounded-buffer, canonical 24-byte field storage. Files are created
/// exclusively (never overwritten), initialized to zero, and removed when
/// their last handle closes unless retain() was requested. The parent must
/// be a private caller-owned directory. A handle is shared, not a table copy.
class ScalarArray {
  public:
    ScalarArray() = default;
    static ScalarArray create(const std::filesystem::path &path,
                              std::size_t count);
    /// Open an existing regular file with exactly count canonical field cells.
    /// The descriptor is read-only and closing it never deletes the file.
    /// Field encodings are checked when read, without a full-file startup scan.
    static ScalarArray open_read_only(const std::filesystem::path &path,
                                      std::size_t count);
    std::size_t size() const;
    void read_block(std::size_t offset, std::span<Fpk> values) const;
    void write_block(std::size_t offset, std::span<const Fpk> values);
    void read(std::size_t offset, std::span<Fpk> values) const {
        read_block(offset, values);
    }
    void write(std::size_t offset, std::span<const Fpk> values) {
        write_block(offset, values);
    }
    Fpk get(std::size_t offset) const;
    void set(std::size_t offset, const Fpk &value);
    void retain();
    const std::filesystem::path &path() const;
    explicit operator bool() const { return static_cast<bool>(impl_); }
  private:
    friend Commitment reopen_commitment(const std::filesystem::path &,
                                         const Metadata &);
    static ScalarArray open_read_only_at(int directory_fd,
        const std::filesystem::path &directory, const std::string &name,
        std::size_t count);
    struct Impl;
    explicit ScalarArray(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
    std::shared_ptr<Impl> impl_;
};

/// A reader must fill exactly the requested in-range contiguous block.
/// Readers may generate public tables without ever materializing them.
struct ValueSource {
    std::size_t size = 0;
    std::function<void(std::size_t, std::span<Fpk>)> read;
};
ValueSource source(const ScalarArray &array);
/// The caller must keep the underlying span alive throughout its use.
ValueSource source(std::span<const Fpk> values);

} // namespace laminate::basefold::foldable
#endif
