#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/field/serialization.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <limits>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace laminate::gates {
namespace {
constexpr std::array<std::uint8_t, 16> magic{
    'L','A','M','I','N','A','T','E','-','G','A','T','E','P','K',1};

std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a)
        throw std::overflow_error("GateMLE prover cache size overflow");
    return a + b;
}
std::uint64_t mul(std::uint64_t a, std::uint64_t b) {
    if (b && a > std::numeric_limits<std::uint64_t>::max() / b)
        throw std::overflow_error("GateMLE prover cache size overflow");
    return a * b;
}
std::uint64_t table_bytes(const GateTableVerifierKey &key) {
    if (key.tables.size() != key.layout.tables.size() ||
        !valid_wide_public_index(key))
        throw std::invalid_argument("invalid GateMLE cache verifier key");
    std::uint64_t size = magic.size() + 2 * sizeof(Digest);
    for (std::size_t i = 0; i < key.tables.size(); ++i) {
        const auto &table = key.tables[i];
        const auto &descriptor = key.layout.tables[i];
        if (descriptor.local_variables > 63 ||
            !valid_sparse_table_commitment(descriptor, table, key.basefold_parameters))
            throw std::invalid_argument("invalid GateMLE cache table shape");
        size = add(size, mul(descriptor.support_size, 11));
        if (key.layout.table_set == GateTableSet::Laned) {
            const auto encoded = mul(table.shard_size,
                std::uint64_t{1} << key.basefold_parameters.log_rate);
            size = add(size, mul(mul(table.physical_width,
                add(table.shard_size, encoded)), kSerializedFpBytes));
            size = add(size, mul(mul(2, encoded) - 1, sizeof(basefold::Digest)));
        }
    }
    return size;
}

void sync_directory(const std::filesystem::path &path) {
    const auto resolved = path.empty() ? std::filesystem::path(".") : path;
    const int fd = ::open(resolved.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("cannot open GateMLE cache directory for synchronization");
    const int status = ::fsync(fd);
    ::close(fd);
    if (status) throw std::runtime_error("cannot synchronize GateMLE cache directory");
}

class File {
  public:
    File(const std::filesystem::path &directory, bool write, std::uint64_t expected)
        : writing_(write) {
        const int dir = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dir < 0) throw std::runtime_error("cannot open GateMLE cache directory");
        const int fd = ::openat(dir, "tables.bin", (write ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY) |
                              O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
        ::close(dir);
        if (fd < 0) throw std::runtime_error("cannot open GateMLE cache tables (fresh setup required if missing)");
        struct stat st{};
        if (::fstat(fd, &st) || !S_ISREG(st.st_mode) ||
            (!write && (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) != expected))) {
            ::close(fd);
            throw std::runtime_error("GateMLE cache tables have invalid file type or length");
        }
        file_ = ::fdopen(fd, write ? "wb" : "rb");
        if (!file_) { ::close(fd); throw std::runtime_error("cannot buffer GateMLE cache file"); }
        ::setvbuf(file_, reinterpret_cast<char *>(buffer_.data()), _IOFBF, buffer_.size());
    }
    ~File() { if (file_) ::fclose(file_); }
    File(const File &) = delete;
    void put(std::span<const std::uint8_t> value, bool hash = true) {
        if (!writing_ || ::fwrite(value.data(), 1, value.size(), file_) != value.size())
            throw std::runtime_error("cannot write GateMLE cache");
        if (hash) hash_.update(value);
    }
    void get(std::span<std::uint8_t> value, bool hash = true) {
        if (writing_ || ::fread(value.data(), 1, value.size(), file_) != value.size())
            throw std::runtime_error("truncated GateMLE cache");
        if (hash) hash_.update(value);
    }
    void finish() {
        auto digest = hash_.finish();
        if (writing_) {
            put(digest, false);
            if (::fflush(file_) || ::fsync(::fileno(file_)))
                throw std::runtime_error("cannot flush GateMLE cache");
        } else {
            Digest recorded{}; get(recorded, false);
            if (recorded != digest || ::fgetc(file_) != EOF)
                throw std::runtime_error("GateMLE cache checksum mismatch");
        }
    }
  private:
    bool writing_;
    std::FILE *file_ = nullptr;
    std::array<std::uint8_t, 65536> buffer_{};
    Sha256Hasher hash_;
};

void write_entries(File &file, std::span<const sparse::SparseEntry> entries) {
    for (const auto &entry : entries) {
        std::array<std::uint8_t, 11> bytes{};
        for (std::size_t b = 0; b < 8; ++b)
            bytes[b] = static_cast<std::uint8_t>(entry.address >> (8 * b));
        const auto value = serialize(entry.value);
        std::copy(value.begin(), value.end(), bytes.begin() + 8);
        file.put(bytes);
    }
}
std::vector<sparse::SparseEntry> read_entries(File &file, const GateTableDescriptor &descriptor) {
    std::vector<sparse::SparseEntry> entries;
    entries.reserve(descriptor.support_size);
    for (std::size_t i = 0; i < descriptor.support_size; ++i) {
        std::array<std::uint8_t, 11> bytes{}; file.get(bytes);
        std::uint64_t address = 0;
        for (std::size_t b = 0; b < 8; ++b) address |= std::uint64_t{bytes[b]} << (8 * b);
        const auto value = deserialize_fp(std::span(bytes).subspan(8));
        if (address >= (std::uint64_t{1} << descriptor.local_variables) || value.is_zero() ||
            (!entries.empty() && address <= entries.back().address))
            throw std::runtime_error("noncanonical GateMLE cache sparse entries");
        entries.push_back({static_cast<std::size_t>(address), value});
    }
    return entries;
}
void write_columns(File &file, const std::vector<std::vector<Fp>> &columns) {
    for (const auto &column : columns) for (const auto &value : column) file.put(serialize(value));
}
std::vector<std::vector<Fp>> read_columns(File &file, std::size_t width, std::size_t rows) {
    std::vector<std::vector<Fp>> columns(width, std::vector<Fp>(rows));
    for (auto &column : columns) for (auto &value : column) {
        SerializedFp bytes{}; file.get(bytes); value = deserialize_fp(bytes);
    }
    return columns;
}
}

void export_gate_table_prover_key(const GateTableProverKey &key,
                                 const std::filesystem::path &directory) {
    const auto expected = table_bytes(key.verifier);
    if (key.tables.size() != key.verifier.tables.size())
        throw std::invalid_argument("GateMLE cache source table count mismatch");
    if (!std::filesystem::create_directory(directory))
        throw std::runtime_error("GateMLE cache destination must be new");
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    try {
        File file(directory, true, expected);
        file.put(magic);
        file.put(sha256(encode_canonical(key.verifier)));
        for (std::size_t i = 0; i < key.tables.size(); ++i) {
            const auto &table = key.tables[i];
            if (table.verifier != key.verifier.tables[i] ||
                table.entries.size() != key.verifier.layout.tables[i].support_size)
                throw std::invalid_argument("GateMLE cache source table mismatch");
            write_entries(file, table.entries);
            if (key.verifier.layout.table_set == GateTableSet::Laned) {
                if (!table.commitment || table.commitment->root != table.verifier.root ||
                    table.commitment->m != table.verifier.shard_size ||
                    table.commitment->width != table.verifier.physical_width)
                    throw std::invalid_argument("GateMLE cache source RS commitment mismatch");
                write_columns(file, table.commitment->columns);
                write_columns(file, table.commitment->codewords);
                for (const auto &level : table.commitment->tree.levels())
                    for (const auto &node : level) file.put(node);
            }
        }
        file.finish();
        if (key.wide_public_commitment)
            basefold::foldable::export_commitment(*key.wide_public_commitment, directory / "wide");
        sync_directory(directory);
        sync_directory(directory.parent_path());
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
        throw;
    }
}

GateTableProverKey reopen_gate_table_prover_key(
    const GateTableVerifierKey &expected, const std::filesystem::path &directory,
    const GateTableBuildOptions &options) {
    if (options.wide_resources.diagonal_cache_bytes > (64ULL << 20))
        throw std::invalid_argument("GateMLE cache exceeds its 64 MiB admission allowance");
    const auto bytes = table_bytes(expected);
    std::uint64_t entries = 0;
    for (const auto &table : expected.layout.tables) entries = add(entries, table.support_size);
    if (entries > options.max_message_entries)
        throw std::length_error("GateMLE cache exceeds sparse support budget");
    File file(directory, false, bytes);
    std::array<std::uint8_t, magic.size()> recorded{}; file.get(recorded);
    Digest fingerprint{}; file.get(fingerprint);
    if (recorded != magic || fingerprint != sha256(encode_canonical(expected)))
        throw std::runtime_error("GateMLE cache does not match authenticated setup");
    GateTableProverKey result;
    result.verifier = expected;
    result.wide_resources = options.wide_resources;
    result.wide_resources.max_disk_bytes = options.wide_max_disk_bytes
        ? options.wide_max_disk_bytes : (std::uint64_t{1} << 30);
    result.wide_scratch_parent = options.wide_scratch_parent.empty()
        ? std::filesystem::temp_directory_path() : options.wide_scratch_parent;
    for (std::size_t i = 0; i < expected.tables.size(); ++i) {
        SparseTableProverKey table;
        table.verifier = expected.tables[i];
        table.entries = read_entries(file, expected.layout.tables[i]);
        if (expected.layout.table_set == GateTableSet::Laned) {
            const auto m = table.verifier.shard_size;
            const auto n = m << expected.basefold_parameters.log_rate;
            auto columns = read_columns(file, table.verifier.physical_width, m);
            auto codewords = read_columns(file, table.verifier.physical_width, n);
            std::vector<std::vector<basefold::Digest>> levels;
            for (auto count = n; ; count /= 2) {
                auto &level = levels.emplace_back(count);
                for (auto &node : level) file.get(node);
                if (count == 1) break;
            }
            table.commitment.emplace(m, expected.basefold_parameters.log_rate,
                std::move(columns), std::move(codewords),
                basefold::MerkleTree::from_levels(std::move(levels), table.verifier.root));
        }
        result.tables.push_back(std::move(table));
    }
    file.finish();
    if (expected.wide_public_commitment) {
        result.wide_public_commitment = basefold::foldable::reopen_commitment(
            directory / "wide", *expected.wide_public_commitment);
        result.wide_retained_disk_bytes = add(bytes,
            basefold::foldable::retained_commitment_disk_bound(
                expected.wide_public_commitment->m, expected.wide_public_commitment->width));
        if (result.wide_retained_disk_bytes > result.wide_resources.max_disk_bytes)
            throw std::length_error("GateMLE cache exceeds disk budget");
        std::filesystem::create_directories(result.wide_scratch_parent);
    }
    return result;
}
} // namespace laminate::gates
