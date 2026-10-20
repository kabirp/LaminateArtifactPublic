#include "laminate/basefold/foldable.hpp"
#include "laminate/basefold/common.hpp"
#include "laminate/basefold/foldable_query_policy.hpp"
#include "laminate/basefold/reed_solomon.hpp"
#include "laminate/field/serialization.hpp"
#include "laminate/transcript/transcript.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <cerrno>
#include <condition_variable>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <numeric>
#include <set>
#include <stdexcept>
#include <system_error>
#include <sys/stat.h>
#include <thread>
#include <utility>
#include <unistd.h>

namespace laminate::basefold::foldable {
namespace {
// A commitment reuses these workers across bounded CPU blocks. The caller
// participates, so the requested count includes it. Every block completes
// before the caller reads/writes files or releases its buffers.
class CommitmentWorkers {
  public:
    explicit CommitmentWorkers(std::size_t count) {
        try {
            threads_.reserve(count - 1);
            for (std::size_t index = 1; index < count; ++index)
                threads_.emplace_back([this, index] { worker(index); });
        } catch (...) {
            stop();
            throw;
        }
    }
    ~CommitmentWorkers() { stop(); }
    CommitmentWorkers(const CommitmentWorkers &) = delete;
    CommitmentWorkers &operator=(const CommitmentWorkers &) = delete;

    template <class Function>
    void for_each(std::size_t count, const Function &function) {
        // Small tree levels run on the caller to avoid a barrier per hash.
        const auto active = std::min(threads_.size() + 1, (count + 63) / 64);
        if (active <= 1) {
            for (std::size_t i = 0; i < count; ++i)
                function(i);
            return;
        }
        {
            std::lock_guard lock(mutex_);
            count_ = count;
            active_ = active;
            job_ = [&function](std::size_t begin, std::size_t end) {
                for (auto i = begin; i < end; ++i)
                    function(i);
            };
            remaining_ = threads_.size();
            ++generation_;
        }
        ready_.notify_all();
        run_chunk(0);
        std::exception_ptr failure;
        {
            std::unique_lock lock(mutex_);
            done_.wait(lock, [this] { return remaining_ == 0; });
            job_ = {};
            failure = std::exchange(failure_, {});
        }
        if (failure)
            std::rethrow_exception(failure);
    }

  private:
    void run_chunk(std::size_t index) noexcept {
        if (index >= active_)
            return;
        const auto per_thread = count_ / active_, extra = count_ % active_;
        const auto begin = index * per_thread + std::min(index, extra);
        const auto end = begin + per_thread + (index < extra ? 1 : 0);
        try {
            job_(begin, end);
        } catch (...) {
            std::lock_guard lock(mutex_);
            if (!failure_)
                failure_ = std::current_exception();
        }
    }
    void worker(std::size_t index) {
        std::size_t seen = 0;
        std::unique_lock lock(mutex_);
        for (;;) {
            ready_.wait(lock, [&] { return stopping_ || generation_ != seen; });
            if (stopping_)
                return;
            seen = generation_;
            lock.unlock();
            run_chunk(index);
            lock.lock();
            if (--remaining_ == 0)
                done_.notify_one();
        }
    }
    void stop() noexcept {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        ready_.notify_all();
        for (auto &thread : threads_)
            thread.join();
    }

    std::mutex mutex_;
    std::condition_variable ready_, done_;
    std::vector<std::thread> threads_;
    std::function<void(std::size_t, std::size_t)> job_;
    std::exception_ptr failure_;
    std::size_t count_ = 0, active_ = 0, remaining_ = 0, generation_ = 0;
    bool stopping_ = false;
};

template <class Function>
void for_each(CommitmentWorkers *workers, std::size_t count,
              const Function &function) {
    if (workers) {
        workers->for_each(count, function);
    } else {
        for (std::size_t i = 0; i < count; ++i)
            function(i);
    }
}

// One bounded cache belongs to an encoding call or commitment, shared by
// every recursive subtree and column. Complete small levels are reused most
// often. Population finishes before the encoder reads them concurrently.
class DiagonalCache {
  public:
    DiagonalCache(std::size_t max_variables, std::uint64_t bytes,
                  CommitmentWorkers *workers = nullptr) {
        for (auto level = kRsBaseVariables + 1; level <= max_variables; ++level) {
            const auto count = std::size_t{1} << (level + kLogRate - 1);
            if (count > bytes / sizeof(Fpk)) break;
            auto &values = levels_[level];
            values.resize(count);
            for_each(workers, count, [&](std::size_t index) {
                values[index] = diagonal(level, index);
            });
            bytes -= count * sizeof(Fpk);
        }
    }
    Fpk get(std::size_t level, std::size_t index) const {
        const auto &values = levels_[level];
        return values.empty() ? diagonal(level, index) : values[index];
    }
  private:
    std::array<std::vector<Fpk>, kMaxVariables + 1> levels_;
};

std::atomic<std::uint64_t> next_file{0};
std::filesystem::path filename(const std::filesystem::path &directory) {
    return directory / ("foldable-" + std::to_string(::getpid()) + "-" +
                        std::to_string(next_file.fetch_add(1)));
}
void reserve(const std::filesystem::path &directory, std::uint64_t bytes,
             const Options &options) {
    if (options.block_elements == 0 || options.block_elements > 65536 ||
        bytes > options.max_disk_bytes)
        throw std::invalid_argument("foldable: storage/memory resource limit");
    if (!std::filesystem::exists(directory)) {
        std::filesystem::create_directories(directory);
        std::filesystem::permissions(directory,
                                     std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace);
    }
    if (std::filesystem::is_symlink(directory) ||
        !std::filesystem::is_directory(directory))
        throw std::invalid_argument(
            "foldable: expected private scratch directory");
    const auto available = std::filesystem::space(directory).available;
    if (options.min_free_bytes > available ||
        bytes > available - options.min_free_bytes)
        throw std::runtime_error("foldable: insufficient disk reservation");
}
std::uint64_t checked_product(std::uint64_t a, std::uint64_t b) {
    if (b && a > std::numeric_limits<std::uint64_t>::max() / b)
        throw std::length_error("foldable resource arithmetic overflow");
    return a * b;
}
Fp power(Fp a, std::size_t exponent) {
    Fp result = Fp::one();
    while (exponent) {
        if (exponent & 1)
            result *= a;
        a *= a;
        exponent >>= 1;
    }
    return result;
}
bool power_of_two(std::size_t n) { return n && !(n & (n - 1)); }
ScalarArray copy_source(const ValueSource &input,
                        const std::filesystem::path &directory,
                        std::size_t block) {
    if (!input.read)
        throw std::invalid_argument("foldable: missing value source");
    auto out = ScalarArray::create(filename(directory), input.size);
    std::vector<Fpk> buffer(std::min(block, input.size));
    for (std::size_t offset = 0; offset < input.size; offset += buffer.size()) {
        auto values = std::span(buffer).first(
            std::min(buffer.size(), input.size - offset));
        input.read(offset, values);
        out.write_block(offset, values);
    }
    return out;
}
// Recursing on even evaluations and odd-minus-even evaluations implements
// coefficient parity, not contiguous coefficient halves. This is essential:
// both the multilinear sumcheck and the code bind the LSB variable first.
ScalarArray encode_impl(const ValueSource &input,
                        const std::filesystem::path &directory,
                        std::size_t block, CommitmentWorkers *workers = nullptr,
                        const DiagonalCache *cache = nullptr) {
    const auto variables = log2_exact(input.size);
    if (variables <= kRsBaseVariables) {
        std::vector<Fpk> evaluations(input.size);
        input.read(0, evaluations);
        // Public index cells lie in Fp, and parity differences preserve that
        // subfield until this RS leaf. Use the same linear encoder over Fp
        // when possible, then lift its output exactly into Fpk.
        const bool base_only = std::all_of(evaluations.begin(), evaluations.end(),
            [](const Fpk &value) {
                const auto &coefficients = value.coefficients();
                return std::all_of(coefficients.begin() + 1, coefficients.end(),
                                   [](const Fp &coefficient) { return coefficient.is_zero(); });
            });
        std::vector<Fpk> encoded;
        if (base_only) {
            std::vector<Fp> base_values;
            base_values.reserve(evaluations.size());
            for (const auto &value : evaluations)
                base_values.push_back(value.coefficients()[0]);
            const auto base_encoded = reed_solomon_encode(
                evaluations_to_coefficients(base_values), kLogRate);
            encoded.reserve(base_encoded.size());
            for (const auto &value : base_encoded)
                encoded.push_back(Fpk::from_base(value));
        } else {
            encoded = reed_solomon_encode(
                evaluations_to_coefficients(evaluations), kLogRate);
        }
        auto out = ScalarArray::create(filename(directory), encoded.size());
        out.write_block(0, encoded);
        return out;
    }
    const auto half = input.size / 2;
    auto even = ScalarArray::create(filename(directory), half);
    auto delta = ScalarArray::create(filename(directory), half);
    {
        std::vector<Fpk> in(std::min(2 * block, input.size)), lo(in.size() / 2),
            hi(lo.size());
        for (std::size_t off = 0; off < half; off += lo.size()) {
            const auto count = std::min(lo.size(), half - off);
            input.read(2 * off, std::span(in).first(2 * count));
            for_each(workers, count, [&](std::size_t i) {
                lo[i] = in[2 * i];
                hi[i] = in[2 * i + 1] - in[2 * i];
            });
            even.write_block(off, std::span(lo).first(count));
            delta.write_block(off, std::span(hi).first(count));
        }
    }
    auto left = encode_impl(source(even), directory, block, workers, cache);
    even = {};
    auto right = encode_impl(source(delta), directory, block, workers, cache);
    delta = {};
    auto out = ScalarArray::create(filename(directory), input.size << kLogRate);
    std::vector<Fpk> a(std::min(block, left.size())), b(a.size()), lo(a.size()),
        hi(a.size());
    for (std::size_t off = 0; off < left.size(); off += a.size()) {
        const auto count = std::min(a.size(), left.size() - off);
        left.read_block(off, std::span(a).first(count));
        right.read_block(off, std::span(b).first(count));
        for_each(workers, count, [&](std::size_t i) {
            const auto t = (cache ? cache->get(variables, off + i)
                                 : diagonal(variables, off + i)) * b[i];
            lo[i] = a[i] + t;
            hi[i] = a[i] - t;
        });
        out.write_block(off, std::span(lo).first(count));
        out.write_block(left.size() + off, std::span(hi).first(count));
    }
    return out;
}
// A disk tree retains O(n) hashes on disk and only one bounded block in RAM.
class HashFile {
  public:
    HashFile(const std::filesystem::path &path, std::size_t count)
        : path_(path), count_(count) {
        fd_ = ::open(path.c_str(),
                     O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0)
            throw std::system_error(errno, std::generic_category(),
                                    "foldable hash file create");
        if (count >
                static_cast<std::size_t>(std::numeric_limits<off_t>::max()) /
                    Digest{}.size() ||
            ::ftruncate(fd_, static_cast<off_t>(count * Digest{}.size())) !=
                0) {
            const auto saved = errno;
            ::close(fd_);
            std::filesystem::remove(path_);
            throw std::system_error(saved, std::generic_category(),
                                    "foldable hash file size");
        }
    }
    static std::shared_ptr<HashFile> open_read_only_at(
        int directory_fd, const std::filesystem::path &directory,
        const std::string &name, std::size_t count) {
        auto result = std::shared_ptr<HashFile>(new HashFile);
        result->path_ = directory / name;
        result->count_ = count;
        result->remove_ = false;
        result->fd_ = ::openat(directory_fd, name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (result->fd_ < 0)
            throw std::system_error(errno, std::generic_category(),
                                    "open persisted foldable tree");
        struct stat status{};
        if (::fstat(result->fd_, &status) != 0)
            throw std::system_error(errno, std::generic_category(),
                                    "stat persisted foldable tree");
        if (count > static_cast<std::size_t>(std::numeric_limits<off_t>::max()) /
                        Digest{}.size() || !S_ISREG(status.st_mode) ||
            status.st_size < 0 || static_cast<std::uint64_t>(status.st_size) !=
                count * Digest{}.size())
            throw std::invalid_argument("foldable: persisted tree size/type");
        return result;
    }
    ~HashFile() {
        if (fd_ >= 0) ::close(fd_);
        if (remove_) {
            std::error_code ignored;
            std::filesystem::remove(path_, ignored);
        }
    }
    const std::filesystem::path &path() const { return path_; }
    void read(std::size_t offset, std::span<Digest> values) const {
        transfer(offset, values.data(), values.size(), false);
    }
    void write(std::size_t offset, std::span<const Digest> values) {
        transfer(offset, const_cast<Digest *>(values.data()), values.size(),
                 true);
    }

  private:
    HashFile() = default;
    void transfer(std::size_t offset, Digest *values, std::size_t count,
                  bool write) const {
        if (offset > count_ || count > count_ - offset)
            throw std::out_of_range("foldable hash range");
        auto *bytes = reinterpret_cast<std::uint8_t *>(values);
        const auto total = count * Digest{}.size();
        for (std::size_t done = 0; done < total;) {
            const auto at = static_cast<off_t>(offset * Digest{}.size() + done);
            const auto n = write ? ::pwrite(fd_, bytes + done, total - done, at)
                                 : ::pread(fd_, bytes + done, total - done, at);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                throw std::system_error(errno, std::generic_category(),
                                        "foldable hash I/O");
            }
            if (n == 0)
                throw std::runtime_error("truncated foldable hash file");
            done += static_cast<std::size_t>(n);
        }
    }
    std::filesystem::path path_;
    std::size_t count_ = 0;
    int fd_ = -1;
    bool remove_ = true;
};
std::vector<Fpk> pair_values(std::span<const ScalarArray> columns,
                             std::size_t pair) {
    const auto width = columns.size(), half = columns.front().size() / 2;
    std::vector<Fpk> values(2 * width);
    for (std::size_t c = 0; c < width; ++c) {
        values[c] = columns[c].get(pair);
        values[width + c] = columns[c].get(pair + half);
    }
    return values;
}
std::vector<std::size_t> selected_pairs(std::span<const std::size_t> queries,
                                        std::size_t half) {
    std::vector<std::size_t> indices;
    indices.reserve(queries.size());
    for (auto q : queries)
        indices.push_back(q % half);
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
    return indices;
}
std::vector<std::size_t> query_indices(PublicCoin &coin, std::size_t n,
                                       std::size_t count) {
    const auto bits = log2_exact(n);
    const auto random = coin.challenge_bits(bits * count);
    if (random.size() != bits * count)
        throw std::runtime_error("foldable coin returned malformed bits");
    std::vector<std::size_t> result(count);
    for (std::size_t j = 0; j < count; ++j)
        for (std::size_t k = 0; k < bits; ++k)
            if (random[j * bits + k])
                result[j] |= std::size_t{1} << k;
    return result;
}
bool valid_statement(const Metadata &meta, std::size_t operands,
                     std::span<const Fpk> weights, std::span<const Fpk> targets,
                     CommitmentPremise premise, const Parameters &params) {
    return valid_shape(meta, params) && operands > 0 && operands <= 65536 &&
           weights.size() == meta.width && targets.size() == operands &&
           (premise == CommitmentPremise::HonestCodewordColumns ||
            (premise == CommitmentPremise::ArbitrarySingleColumn &&
             meta.width == 1 && weights[0] == Fpk::one()));
}
void bind_statement(const Metadata &meta, std::size_t operands,
                    std::span<const Fpk> weights, std::span<const Fpk> targets,
                    PublicCoin &coin, CommitmentPremise premise,
                    const Parameters &params) {
    coin.observe("foldable/version", kHierarchyVersion);
    coin.observe("foldable/root", meta.root);
    coin.observe("foldable/m", meta.m);
    coin.observe("foldable/width", meta.width);
    coin.observe("foldable/premise", static_cast<std::uint64_t>(premise));
    coin.observe("foldable/queries", params.num_queries);
    coin.observe("foldable/operands", operands);
    coin.observe("foldable/weights", serialize_values(weights));
    coin.observe("foldable/targets", serialize_values(targets));
}
ScalarArray combine(std::span<const ValueSource> tables,
                    std::span<const Fpk> weights,
                    const std::filesystem::path &directory, std::size_t block) {
    auto out = ScalarArray::create(filename(directory), tables.front().size);
    std::vector<Fpk> acc(std::min(block, out.size())), buffer(acc.size());
    for (std::size_t off = 0; off < out.size(); off += acc.size()) {
        const auto n = std::min(acc.size(), out.size() - off);
        std::fill(acc.begin(), acc.end(), Fpk::zero());
        for (std::size_t c = 0; c < tables.size(); ++c) {
            tables[c].read(off, std::span(buffer).first(n));
            for (std::size_t i = 0; i < n; ++i)
                acc[i] += weights[c] * buffer[i];
        }
        out.write_block(off, std::span(acc).first(n));
    }
    return out;
}
bool valid_block_layout(const BlockOperand &operand, std::size_t m) {
    if (!power_of_two(m) || m > (std::size_t{1} << kMaxVariables) ||
        operand.point_lsb.size() > kMaxVariables ||
        !power_of_two(operand.column_weights.size()) ||
        operand.column_weights.size() > 256)
        return false;
    const auto columns = log2_exact(operand.column_weights.size());
    if (operand.point_lsb.size() + columns > kMaxVariables)
        return false;
    const auto size = std::size_t{1} << (operand.point_lsb.size() + columns);
    return operand.offset % size == 0 && operand.offset <= m &&
           size <= m - operand.offset;
}
void bind_block_operands(std::span<const BlockOperand> operands,
                         PublicCoin &coin) {
    coin.observe("foldable/block-operands/version", std::uint64_t{1});
    coin.observe("foldable/block-operands/count", operands.size());
    for (const auto &operand : operands) {
        coin.observe("foldable/block-operands/offset", operand.offset);
        coin.observe("foldable/block-operands/row-variables",
                     operand.point_lsb.size());
        coin.observe("foldable/block-operands/point",
                     serialize_values(operand.point_lsb));
        coin.observe("foldable/block-operands/columns",
                     operand.column_weights.size());
        coin.observe("foldable/block-operands/weights",
                     serialize_values(operand.column_weights));
    }
}
// Add a supported slice in linear work and bounded memory. Split each row
// range into aligned dyadic pieces, so equality tables never exceed the I/O
// chunk. No inversion is used; Boolean coordinates zero and one work too.
void add_block_slice(const BlockOperand &operand, const Fpk &weight,
                     std::size_t offset, std::span<Fpk> result) {
    const auto rows = std::size_t{1} << operand.point_lsb.size();
    const auto point = std::span(operand.point_lsb);
    for (std::size_t done = 0; done < result.size();) {
        const auto relative = offset + done - operand.offset;
        const auto row = relative % rows, column = relative / rows;
        auto count = std::bit_floor(std::min(result.size() - done, rows - row));
        if (row)
            count = std::min(count, std::size_t{1} << std::countr_zero(row));
        const auto variables =
            static_cast<std::size_t>(std::countr_zero(count));
        const auto scale =
            weight * operand.column_weights[column] *
            equality_evaluation(row >> variables, point.subspan(variables));
        const auto low = equality_evaluations(point.first(variables));
        for (std::size_t i = 0; i < count; ++i)
            result[done + i] += scale * low[i];
        done += count;
    }
}
ScalarArray combine_blocks(std::span<const BlockOperand> operands,
                           std::span<const Fpk> weights, std::size_t m,
                           const std::filesystem::path &directory,
                           std::size_t block) {
    // A newly created ScalarArray is zero-filled. An interval sweep writes
    // each supported chunk once and never visits gaps or absent operands.
    struct Event {
        std::size_t offset, index;
        bool start;
    };
    std::vector<Event> events;
    events.reserve(2 * operands.size());
    for (std::size_t i = 0; i < operands.size(); ++i) {
        events.push_back({operands[i].offset, i, true});
        events.push_back(
            {operands[i].offset + block_operand_size(operands[i]), i, false});
    }
    std::sort(events.begin(), events.end(), [](const Event &a, const Event &b) {
        return a.offset < b.offset;
    });
    auto result = ScalarArray::create(filename(directory), m);
    std::vector<Fpk> values(std::min(block, m));
    std::set<std::size_t> active;
    for (std::size_t e = 0; e < events.size();) {
        const auto begin = events[e].offset;
        do {
            const auto &event = events[e++];
            if (event.start)
                active.insert(event.index);
            else
                active.erase(event.index);
        } while (e < events.size() && events[e].offset == begin);
        if (e == events.size() || active.empty())
            continue;
        const auto end = events[e].offset;
        for (auto offset = begin; offset < end;) {
            const auto count = std::min(values.size(), end - offset);
            auto chunk = std::span(values).first(count);
            std::fill(chunk.begin(), chunk.end(), Fpk::zero());
            for (const auto index : active)
                add_block_slice(operands[index], weights[index], offset, chunk);
            result.write_block(offset, chunk);
            offset += count;
        }
    }
    return result;
}
ScalarArray fold_table(const ScalarArray &input, const Fpk &challenge,
                       const std::filesystem::path &directory,
                       std::size_t block) {
    auto out = ScalarArray::create(filename(directory), input.size() / 2);
    std::vector<Fpk> buffer(std::min(2 * block, input.size())),
        values(buffer.size() / 2);
    for (std::size_t off = 0; off < out.size(); off += values.size()) {
        const auto n = std::min(values.size(), out.size() - off);
        input.read_block(2 * off, std::span(buffer).first(2 * n));
        for (std::size_t i = 0; i < n; ++i)
            values[i] =
                buffer[2 * i] + challenge * (buffer[2 * i + 1] - buffer[2 * i]);
        out.write_block(off, std::span(values).first(n));
    }
    return out;
}
std::array<Fpk, 3> sumcheck_round(const ScalarArray &a, const ScalarArray &b,
                                  std::size_t block) {
    std::array<Fpk, 3> result{};
    std::vector<Fpk> av(std::min(2 * block, a.size())), bv(av.size());
    for (std::size_t off = 0; off < a.size(); off += av.size()) {
        const auto n = std::min(av.size(), a.size() - off);
        a.read_block(off, std::span(av).first(n));
        b.read_block(off, std::span(bv).first(n));
        for (std::size_t i = 0; i < n; i += 2) {
            result[0] += av[i] * bv[i];
            result[1] += av[i + 1] * bv[i + 1];
            result[2] += (av[i + 1] + av[i + 1] - av[i]) *
                         (bv[i + 1] + bv[i + 1] - bv[i]);
        }
    }
    return result;
}
ScalarArray fold_oracle(const ScalarArray &input, const Fpk &challenge,
                        std::size_t variables,
                        const std::filesystem::path &directory,
                        std::size_t block) {
    auto out = ScalarArray::create(filename(directory), input.size() / 2);
    std::vector<Fpk> lo(std::min(block, out.size())), hi(lo.size()),
        d(lo.size()), prefix(lo.size());
    const auto inv2 = Fp(2).inverse();
    for (std::size_t off = 0; off < out.size(); off += lo.size()) {
        const auto n = std::min(lo.size(), out.size() - off);
        input.read_block(off, std::span(lo).first(n));
        input.read_block(off + out.size(), std::span(hi).first(n));
        Fpk product = Fpk::one();
        for (std::size_t i = 0; i < n; ++i) {
            d[i] = diagonal(variables, off + i);
            prefix[i] = product;
            product *= d[i];
        }
        auto inverse = product.inverse();
        for (std::size_t i = n; i-- > 0;) {
            const auto tmp = inverse * prefix[i];
            inverse *= d[i];
            d[i] = tmp;
        }
        for (std::size_t i = 0; i < n; ++i)
            lo[i] =
                (lo[i] + hi[i] + challenge * ((lo[i] - hi[i]) * d[i])) * inv2;
        out.write_block(off, std::span(lo).first(n));
    }
    return out;
}
Fpk evaluate_source(const ValueSource &input, std::span<const Fpk> point,
                    const std::filesystem::path &directory, std::size_t block) {
    auto current = copy_source(input, directory, block);
    for (const auto &r : point)
        current = fold_table(current, r, directory, block);
    return current.get(0);
}
} // namespace

struct Commitment::Authentication {
    std::shared_ptr<HashFile> hashes;
    std::vector<std::size_t> offsets;
    std::size_t leaves = 0;
    Digest root{};
};
namespace {
std::shared_ptr<Commitment::Authentication>
build_tree(std::span<const ScalarArray> columns,
           const std::filesystem::path &directory, std::size_t block,
           CommitmentWorkers *workers = nullptr) {
    auto tree = std::make_shared<Commitment::Authentication>();
    tree->leaves = columns.front().size() / 2;
    tree->hashes =
        std::make_shared<HashFile>(filename(directory), 2 * tree->leaves - 1);
    std::size_t total = 0;
    for (auto n = tree->leaves; n; n /= 2) {
        tree->offsets.push_back(total);
        total += n;
    }
    const auto width = columns.size();
    const auto chunk =
        std::min(std::max<std::size_t>(1, block / (2 * width)), tree->leaves);
    std::vector<Fpk> lo(chunk), hi(chunk);
    // Hash an entire chunk at once. Width is public and bounded by 256.
    std::vector<Fpk> cells(2 * width * chunk);
    std::vector<Digest> hashes(chunk);
    for (std::size_t off = 0; off < tree->leaves; off += chunk) {
        const auto n = std::min(chunk, tree->leaves - off);
        for (std::size_t c = 0; c < width; ++c) {
            columns[c].read_block(off, std::span(lo).first(n));
            columns[c].read_block(off + tree->leaves, std::span(hi).first(n));
            for (std::size_t i = 0; i < n; ++i) {
                cells[i * 2 * width + c] = lo[i];
                cells[i * 2 * width + width + c] = hi[i];
            }
        }
        for_each(workers, n, [&](std::size_t i) {
            hashes[i] = MerkleTree::hash_leaf(serialize_values(
                std::span(cells).subspan(i * 2 * width, 2 * width)));
        });
        tree->hashes->write(off, std::span(hashes).first(n));
    }
    std::vector<Digest> children(2 * chunk), parents(chunk);
    for (std::size_t level = 1; level < tree->offsets.size(); ++level) {
        const auto size = tree->leaves >> level;
        for (std::size_t off = 0; off < size; off += chunk) {
            const auto n = std::min(chunk, size - off);
            tree->hashes->read(tree->offsets[level - 1] + 2 * off,
                               std::span(children).first(2 * n));
            for_each(workers, n, [&](std::size_t i) {
                parents[i] = MerkleTree::hash_children(children[2 * i],
                                                       children[2 * i + 1]);
            });
            tree->hashes->write(tree->offsets[level] + off,
                                std::span(parents).first(n));
        }
    }
    tree->hashes->read(total - 1, std::span(&tree->root, 1));
    return tree;
}
MultiOpening open_many(std::span<const ScalarArray> columns,
                       const Commitment::Authentication &tree,
                       std::span<const std::size_t> queries) {
    const auto indices = selected_pairs(queries, tree.leaves);
    MultiOpening result;
    result.values.reserve(indices.size() * 2 * columns.size());
    for (auto i : indices) {
        const auto values = pair_values(columns, i);
        result.values.insert(result.values.end(), values.begin(), values.end());
    }
    for (const auto p :
         MerkleTree::multiproof_frontier_positions(tree.leaves, indices)) {
        Digest d;
        tree.hashes->read(tree.offsets[p.level] + p.index, std::span(&d, 1));
        result.frontier.push_back(d);
    }
    return result;
}
bool verify_many(const Digest &root, std::size_t n, std::size_t width,
                 std::span<const std::size_t> queries,
                 const MultiOpening &opening) {
    const auto indices = selected_pairs(queries, n / 2);
    if (opening.values.size() != indices.size() * 2 * width)
        return false;
    std::vector<Digest> hashes;
    hashes.reserve(indices.size());
    for (std::size_t i = 0; i < indices.size(); ++i)
        hashes.push_back(MerkleTree::hash_leaf(serialize_values(
            std::span(opening.values).subspan(2 * width * i, 2 * width))));
    return MerkleTree::verify_many_hashes(root, n / 2, indices, hashes,
                                          opening.frontier);
}
std::span<const Fpk> lookup(const MultiOpening &opening,
                            std::span<const std::size_t> indices,
                            std::size_t pair, std::size_t width) {
    const auto at = std::lower_bound(indices.begin(), indices.end(), pair) -
                    indices.begin();
    return std::span(opening.values)
        .subspan(static_cast<std::size_t>(at) * 2 * width, 2 * width);
}
}

bool distance_certificate() {
    std::uint64_t n = 65536, t = 8192;
    for (std::size_t level = 14; level <= kMaxVariables; ++level) {
        const auto logn = level + 2; // Parent length = 2^(level-1+3).
        const auto numerator = logn + 5 * n / 4 + 2 * t + 129;
        const auto slack = (numerator + 125) / 126;
        t = 2 * t + slack;
        n *= 2;
        if (3 * t >= n)
            return false;
    }
    return true;
}
bool valid_shape(const Metadata &meta, const Parameters &params) {
    return meta.hierarchy_version == kHierarchyVersion &&
           power_of_two(meta.m) &&
           meta.m <= (std::size_t{1} << kMaxVariables) && meta.width > 0 &&
           meta.width <= 256 &&
           admitted_query_count(meta.m, params.num_queries) &&
           distance_certificate();
}
std::size_t conservative_rbr_soundness_bits(const Metadata &meta,
                                            const Parameters &params,
                                            CommitmentPremise premise) {
    if (!valid_shape(meta, params) ||
        (premise != CommitmentPremise::HonestCodewordColumns &&
         !(premise == CommitmentPremise::ArbitrarySingleColumn &&
           meta.width == 1)))
        return 0;
    return 110;
}
std::uint64_t commitment_disk_bound(std::size_t m, std::size_t width) {
    // Recursive encoding peaks below the later retained-tree phase:
    // E(m)<=384m, so previous columns + current message + E(m) is
    // (216*width+192)m, versus (216*width+320)m for the retained tree.
    return retained_commitment_disk_bound(m, width);
}
std::uint64_t retained_commitment_disk_bound(std::size_t m, std::size_t width) {
    // 9m field elements per column; 8m-1 hashes in the paired-leaf tree.
    // Retain an extra digest of conservative slack rather than subtracting.
    return checked_product(m, checked_product(width, 9 * 24) + 8 * 40);
}
std::uint64_t proving_disk_bound(std::size_t m, std::size_t operands,
                                 bool reuse) {
    (void)operands; // Only one batched operand is materialized.
    // All code oracles <384m bytes, all trees <320m. Temporary sumcheck
    // folds peak below that phase; evaluating one terminal operand adds
    // at most 36m bytes. Unit-weight single-column openings alias 216m
    // bytes of the already-retained initial message and codeword.
    return checked_product(m, reuse ? 524 : 740);
}
Fpk diagonal(std::size_t variables, std::size_t index) {
    if (variables == 0 || variables > kMaxVariables ||
        index >= (std::size_t{1} << (variables + kLogRate - 1)))
        throw std::invalid_argument("foldable: diagonal outside hierarchy");
    if (variables <= kRsBaseVariables)
        return Fpk::from_base(
            power(Fp::two_adic_generator(variables + kLogRate), index));
    // Cache the unsampled prefix once per level and worker. Each call copies
    // it, observes the index, and rejection-samples a nonzero diagonal entry.
    thread_local std::array<std::optional<Transcript>, kMaxVariables + 1> prefixes;
    auto &prefix = prefixes[variables];
    if (!prefix) {
        prefix.emplace("Laminate/FoldableGateCode/UniversalDiagonal/v1");
        prefix->observe("version", kHierarchyVersion);
        prefix->observe("level", variables);
    }
    auto oracle = *prefix;
    oracle.observe("index", index);
    Fpk value;
    do {
        value = oracle.challenge_fpk();
    } while (value.is_zero());
    return value;
}
ScalarArray encode(const ValueSource &input,
                   const std::filesystem::path &directory,
                   const Options &options) {
    if (!valid_shape(Metadata{{}, input.size, 1}) || !input.read)
        throw std::invalid_argument("foldable: invalid encoding shape");
    reserve(directory, commitment_disk_bound(input.size, 1), options);
    const DiagonalCache cache(log2_exact(input.size), options.diagonal_cache_bytes);
    return encode_impl(input, directory, options.block_elements, nullptr, &cache);
}
Commitment commit(std::span<const ValueSource> columns,
                  const std::filesystem::path &directory,
                  const Options &options, std::size_t worker_threads) {
    if (worker_threads == 0 || worker_threads > 256)
        throw std::invalid_argument("foldable: worker count must be in [1, 256]");
    if (columns.empty() ||
        !valid_shape(Metadata{{}, columns.front().size, columns.size()}))
        throw std::invalid_argument("foldable: invalid commitment shape");
    for (const auto &c : columns)
        if (c.size != columns.front().size || !c.read)
            throw std::invalid_argument("foldable: inconsistent columns");
    reserve(directory,
            commitment_disk_bound(columns.front().size, columns.size()),
            options);
    CommitmentWorkers workers(worker_threads);
    const DiagonalCache cache(log2_exact(columns.front().size),
                               options.diagonal_cache_bytes, &workers);
    Commitment result;
    result.metadata.m = columns.front().size;
    result.metadata.width = columns.size();
    for (const auto &c : columns) {
        result.columns.push_back(
            copy_source(c, directory, options.block_elements));
        result.codewords.push_back(encode_impl(
            source(result.columns.back()), directory, options.block_elements,
            &workers, &cache));
    }
    result.authentication =
        build_tree(result.codewords, directory, options.block_elements, &workers);
    result.metadata.root = result.authentication->root;
    return result;
}
namespace {
class FileDescriptor {
  public:
    explicit FileDescriptor(int fd) : fd_(fd) {
        if (fd < 0)
            throw std::system_error(errno, std::generic_category(),
                                    "foldable persistence open");
    }
    ~FileDescriptor() { ::close(fd_); }
    FileDescriptor(const FileDescriptor &) = delete;
    FileDescriptor &operator=(const FileDescriptor &) = delete;
    int get() const { return fd_; }
  private:
    int fd_;
};
void check_file_size(int fd, std::uint64_t bytes) {
    struct stat status{};
    if (::fstat(fd, &status) != 0)
        throw std::system_error(errno, std::generic_category(),
                                "foldable persistence stat");
    if (!S_ISREG(status.st_mode) || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) != bytes)
        throw std::invalid_argument("foldable: persisted file size/type");
}
void sync_file(int fd) {
    if (::fsync(fd) != 0)
        throw std::system_error(errno, std::generic_category(),
                                "foldable persistence sync");
}
void transfer_bytes(int fd, std::span<std::uint8_t> bytes, bool write) {
    for (std::size_t done = 0; done < bytes.size();) {
        const auto n = write ? ::write(fd, bytes.data() + done, bytes.size() - done)
                             : ::read(fd, bytes.data() + done, bytes.size() - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(),
                                    "foldable persistence I/O");
        }
        if (n == 0) throw std::runtime_error("foldable: truncated persisted file");
        done += static_cast<std::size_t>(n);
    }
}
std::vector<std::uint8_t> commitment_manifest(const Metadata &metadata) {
    std::vector<std::uint8_t> bytes{'L','M','F','P','C','S','0','1'};
    for (const auto value : std::array<std::uint64_t, 4>{
             metadata.m, metadata.width, metadata.hierarchy_version,
             kSerializedFpkBytes})
        for (std::size_t i = 0; i < 8; ++i)
            bytes.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    bytes.insert(bytes.end(), metadata.root.begin(), metadata.root.end());
    return bytes;
}
void export_file(const std::filesystem::path &source, int directory_fd,
                 const std::string &name, std::uint64_t bytes) {
    const FileDescriptor input(::open(source.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    check_file_size(input.get(), bytes);
    // linkat does not follow the final source symlink. Check the linked inode
    // against the descriptor too, so a replaced source path cannot slip in.
    if (::linkat(AT_FDCWD, source.c_str(), directory_fd, name.c_str(), 0) == 0) {
        const FileDescriptor output(::openat(directory_fd, name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        check_file_size(output.get(), bytes);
        struct stat original{}, linked{};
        if (::fstat(input.get(), &original) != 0 ||
            ::fstat(output.get(), &linked) != 0)
            throw std::system_error(errno, std::generic_category(),
                                    "foldable persistence inode check");
        if (original.st_dev != linked.st_dev || original.st_ino != linked.st_ino)
            throw std::invalid_argument("foldable: source changed during export");
        sync_file(output.get());
        return;
    }
    if (errno != EXDEV)
        throw std::system_error(errno, std::generic_category(),
                                "foldable persistence link");
    const FileDescriptor output(::openat(directory_fd, name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    std::vector<std::uint8_t> buffer(1U << 20);
    for (std::uint64_t offset = 0; offset < bytes;) {
        auto part = std::span(buffer).first(static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), bytes - offset)));
        transfer_bytes(input.get(), part, false);
        transfer_bytes(output.get(), part, true);
        offset += part.size();
    }
    check_file_size(input.get(), bytes);
    sync_file(output.get());
}
} // namespace

void export_commitment(const Commitment &commitment,
                       const std::filesystem::path &directory) {
    const auto &metadata = commitment.metadata;
    if (!valid_shape(metadata) || commitment.columns.size() != metadata.width ||
        commitment.codewords.size() != metadata.width ||
        !commitment.authentication ||
        commitment.authentication->root != metadata.root ||
        commitment.authentication->leaves != metadata.m * 4)
        throw std::invalid_argument("foldable: invalid commitment to export");
    for (std::size_t i = 0; i < metadata.width; ++i)
        if (commitment.columns[i].size() != metadata.m ||
            commitment.codewords[i].size() != metadata.m * 8)
            throw std::invalid_argument("foldable: invalid export column shape");
    if (::mkdir(directory.c_str(), 0700) != 0)
        throw std::system_error(errno, std::generic_category(),
                                "create exclusive foldable persistence directory");
    try {
        const FileDescriptor dir(::open(directory.c_str(),
            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
        for (std::size_t i = 0; i < metadata.width; ++i) {
            export_file(commitment.columns[i].path(), dir.get(),
                "column-" + std::to_string(i), metadata.m * kSerializedFpkBytes);
            export_file(commitment.codewords[i].path(), dir.get(),
                "codeword-" + std::to_string(i), metadata.m * 8 * kSerializedFpkBytes);
        }
        export_file(commitment.authentication->hashes->path(), dir.get(),
            "tree", (metadata.m * 8 - 1) * Digest{}.size());
        auto manifest = commitment_manifest(metadata);
        const FileDescriptor output(::openat(dir.get(), "manifest",
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
        transfer_bytes(output.get(), manifest, true);
        sync_file(output.get());
        sync_file(dir.get());
        const auto parent = directory.parent_path().empty()
            ? std::filesystem::path(".") : directory.parent_path();
        const FileDescriptor parent_fd(::open(parent.c_str(),
            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
        sync_file(parent_fd.get());
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
        throw;
    }
}

Commitment reopen_commitment(const std::filesystem::path &directory,
                            const Metadata &expected) {
    if (!valid_shape(expected))
        throw std::invalid_argument("foldable: invalid expected persisted shape");
    const FileDescriptor dir(::open(directory.c_str(),
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
    const FileDescriptor manifest_file(::openat(dir.get(), "manifest",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    const auto canonical = commitment_manifest(expected);
    check_file_size(manifest_file.get(), canonical.size());
    std::vector<std::uint8_t> manifest(canonical.size());
    transfer_bytes(manifest_file.get(), manifest, false);
    if (manifest != canonical)
        throw std::invalid_argument("foldable: persisted metadata mismatch");
    Commitment result;
    result.metadata = expected;
    for (std::size_t i = 0; i < expected.width; ++i) {
        result.columns.push_back(ScalarArray::open_read_only_at(
            dir.get(), directory, "column-" + std::to_string(i), expected.m));
        result.codewords.push_back(ScalarArray::open_read_only_at(
            dir.get(), directory, "codeword-" + std::to_string(i), expected.m * 8));
    }
    auto tree = std::make_shared<Commitment::Authentication>();
    tree->leaves = expected.m * 4;
    tree->hashes = HashFile::open_read_only_at(dir.get(), directory,
                                             "tree", 2 * tree->leaves - 1);
    std::size_t offset = 0;
    for (auto count = tree->leaves; count; count /= 2) {
        tree->offsets.push_back(offset);
        offset += count;
    }
    tree->hashes->read(offset - 1, std::span(&tree->root, 1));
    if (tree->root != expected.root)
        throw std::invalid_argument("foldable: persisted authentication root mismatch");
    result.authentication = std::move(tree);
    return result;
}

namespace {
template <class Bind, class Combine, class Evaluate>
ProverOutput prove_impl(const Commitment &commitment, std::size_t operand_count,
                        std::span<const Fpk> weights,
                        std::span<const Fpk> targets, PublicCoin &coin,
                        const std::filesystem::path &scratch,
                        CommitmentPremise premise, const Parameters &params,
                        const Options &options, Bind bind_operands,
                        Combine make_operand, Evaluate evaluate_operands) {
    const auto &meta = commitment.metadata;
    if (!valid_statement(meta, operand_count, weights, targets, premise,
                         params) ||
        commitment.columns.size() != meta.width ||
        commitment.codewords.size() != meta.width ||
        !commitment.authentication ||
        commitment.authentication->root != meta.root ||
        commitment.authentication->leaves != meta.m * 4)
        throw std::invalid_argument("foldable: invalid proving statement");
    for (std::size_t c = 0; c < meta.width; ++c)
        if (commitment.columns[c].size() != meta.m ||
            commitment.codewords[c].size() != meta.m * 8)
            throw std::invalid_argument("foldable: malformed column storage");
    const bool reuse = meta.width == 1 && weights[0] == Fpk::one();
    reserve(scratch, proving_disk_bound(meta.m, operand_count, reuse), options);
    bind_operands();
    bind_statement(meta, operand_count, weights, targets, coin, premise,
                   params);
    const auto batching = coin.challenge_vector(operand_count);
    if (batching.size() != operand_count)
        throw std::runtime_error("foldable: malformed batching coin");
    std::vector<ValueSource> messages, codes;
    for (const auto &c : commitment.columns)
        messages.push_back(source(c));
    for (const auto &c : commitment.codewords)
        codes.push_back(source(c));
    auto message =
        reuse ? commitment.columns[0]
              : combine(messages, weights, scratch, options.block_elements);
    auto operand = make_operand(batching);
    std::vector<ScalarArray> layers{
        reuse ? commitment.codewords[0]
              : combine(codes, weights, scratch, options.block_elements)};
    std::vector<std::shared_ptr<Commitment::Authentication>> trees;
    ProverOutput result;
    const auto mu = log2_exact(meta.m);
    for (std::size_t r = 0; r < mu; ++r) {
        auto round = sumcheck_round(message, operand, options.block_elements);
        result.proof.sumcheck.rounds.push_back(round);
        coin.observe("basefold/round", serialize_values(round));
        const auto challenge = coin.challenge_fpk();
        result.reduction.point.push_back(challenge);
        message =
            fold_table(message, challenge, scratch, options.block_elements);
        operand =
            fold_table(operand, challenge, scratch, options.block_elements);
        layers.push_back(fold_oracle(layers.back(), challenge, mu - r, scratch,
                                     options.block_elements));
        if (r + 1 < mu) {
            trees.push_back(build_tree(std::span(&layers.back(), 1), scratch,
                                       options.block_elements));
            result.proof.roots.push_back(trees.back()->root);
            coin.observe("foldable/oracle", trees.back()->root);
        }
    }
    result.proof.sumcheck.operand_evaluations =
        evaluate_operands(result.reduction.point);
    observe_operand_evaluations(result.proof.sumcheck.operand_evaluations,
                                coin);
    result.proof.final_codeword.resize(8);
    layers.back().read_block(0, result.proof.final_codeword);
    coin.observe("foldable/final",
                 serialize_values(result.proof.final_codeword));
    const auto queries = query_indices(coin, meta.m * 8, params.num_queries);
    result.proof.initial =
        open_many(commitment.codewords, *commitment.authentication, queries);
    for (std::size_t r = 0; r < trees.size(); ++r)
        result.proof.folded.push_back(
            open_many(std::span(&layers[r + 1], 1), *trees[r], queries));
    result.reduction.operand_evaluations =
        result.proof.sumcheck.operand_evaluations;
    return result;
}
} // namespace

std::size_t block_operand_size(const BlockOperand &operand) {
    if (operand.point_lsb.size() > kMaxVariables ||
        !power_of_two(operand.column_weights.size()) ||
        operand.column_weights.size() > 256)
        throw std::invalid_argument(
            "foldable: malformed block operand dimensions");
    const auto variables =
        operand.point_lsb.size() + log2_exact(operand.column_weights.size());
    if (variables > kMaxVariables)
        throw std::invalid_argument(
            "foldable: block operand exceeds hierarchy");
    return std::size_t{1} << variables;
}
Fpk evaluate_block_operand(const BlockOperand &operand, std::size_t m,
                           std::span<const Fpk> point) {
    if (!valid_block_layout(operand, m) || point.size() != log2_exact(m))
        throw std::invalid_argument(
            "foldable: malformed block operand layout or point");
    const auto row_variables = operand.point_lsb.size();
    const auto column_variables = log2_exact(operand.column_weights.size());
    Fpk value = Fpk::one();
    for (std::size_t i = 0; i < row_variables; ++i)
        value *=
            ((Fpk::one() - operand.point_lsb[i]) * (Fpk::one() - point[i]) +
             operand.point_lsb[i] * point[i]);
    value *= evaluate_multilinear(
        operand.column_weights, point.subspan(row_variables, column_variables));
    const auto local_variables = row_variables + column_variables;
    return value * equality_evaluation(operand.offset >> local_variables,
                                       point.subspan(local_variables));
}
ProverOutput prove(const Commitment &commitment,
                   std::span<const ValueSource> operands,
                   std::span<const Fpk> weights, std::span<const Fpk> targets,
                   PublicCoin &coin, const std::filesystem::path &scratch,
                   CommitmentPremise premise, const Parameters &params,
                   const Options &options) {
    for (const auto &o : operands)
        if (o.size != commitment.metadata.m || !o.read)
            throw std::invalid_argument("foldable: malformed operand");
    return prove_impl(
        commitment, operands.size(), weights, targets, coin, scratch, premise,
        params, options, [] {},
        [&](std::span<const Fpk> batching) {
            return combine(operands, batching, scratch, options.block_elements);
        },
        [&](std::span<const Fpk> point) {
            std::vector<Fpk> evaluations;
            evaluations.reserve(operands.size());
            for (const auto &o : operands)
                evaluations.push_back(
                    evaluate_source(o, point, scratch, options.block_elements));
            return evaluations;
        });
}
ProverOutput prove_blocks(const Commitment &commitment,
                          std::span<const BlockOperand> operands,
                          std::span<const Fpk> weights,
                          std::span<const Fpk> targets, PublicCoin &coin,
                          const std::filesystem::path &scratch,
                          CommitmentPremise premise, const Parameters &params,
                          const Options &options) {
    for (const auto &o : operands)
        if (!valid_block_layout(o, commitment.metadata.m))
            throw std::invalid_argument(
                "foldable: malformed block operand layout");
    return prove_impl(
        commitment, operands.size(), weights, targets, coin, scratch, premise,
        params, options, [&] { bind_block_operands(operands, coin); },
        [&](std::span<const Fpk> batching) {
            return combine_blocks(operands, batching, commitment.metadata.m,
                                  scratch, options.block_elements);
        },
        [&](std::span<const Fpk> point) {
            std::vector<Fpk> evaluations;
            evaluations.reserve(operands.size());
            for (const auto &o : operands)
                evaluations.push_back(
                    evaluate_block_operand(o, commitment.metadata.m, point));
            return evaluations;
        });
}
std::optional<OperandReduction>
verify(const Metadata &meta, std::size_t operands, std::span<const Fpk> weights,
       std::span<const Fpk> targets, const Proof &proof, PublicCoin &coin,
       CommitmentPremise premise, const Parameters &params) {
    if (!valid_statement(meta, operands, weights, targets, premise, params))
        return std::nullopt;
    const auto mu = log2_exact(meta.m), nonterminal = mu ? mu - 1 : 0;
    if (proof.sumcheck.rounds.size() != mu ||
        proof.sumcheck.operand_evaluations.size() != operands ||
        proof.roots.size() != nonterminal ||
        proof.folded.size() != nonterminal || proof.final_codeword.size() != 8)
        return std::nullopt;
    bind_statement(meta, operands, weights, targets, coin, premise, params);
    const auto batching = coin.challenge_vector(operands);
    if (batching.size() != operands)
        return std::nullopt;
    Fpk claim;
    for (std::size_t j = 0; j < operands; ++j)
        claim += batching[j] * targets[j];
    SumcheckVerifier sumcheck(claim);
    for (std::size_t r = 0; r < mu; ++r) {
        if (!sumcheck.verify_round(proof.sumcheck.rounds[r], coin))
            return std::nullopt;
        if (r + 1 < mu)
            coin.observe("foldable/oracle", proof.roots[r]);
    }
    observe_operand_evaluations(proof.sumcheck.operand_evaluations, coin);
    for (const auto &value : proof.final_codeword)
        if (value != proof.final_codeword.front())
            return std::nullopt;
    if (!sumcheck.verify_terminal(proof.final_codeword.front(), batching,
                                  proof.sumcheck.operand_evaluations))
        return std::nullopt;
    coin.observe("foldable/final", serialize_values(proof.final_codeword));
    const auto queries = query_indices(coin, meta.m * 8, params.num_queries);
    if (!verify_many(meta.root, meta.m * 8, meta.width, queries, proof.initial))
        return std::nullopt;
    std::vector<std::vector<std::size_t>> indices{
        selected_pairs(queries, meta.m * 4)};
    for (std::size_t r = 0; r < nonterminal; ++r) {
        const auto n = (meta.m * 8) >> (r + 1);
        if (!verify_many(proof.roots[r], n, 1, queries, proof.folded[r]))
            return std::nullopt;
        indices.push_back(selected_pairs(queries, n / 2));
    }
    const auto inv2 = Fp(2).inverse();
    for (auto query : queries) {
        if (mu == 0) {
            const auto pair =
                lookup(proof.initial, indices[0], query % 4, meta.width);
            Fpk lo, hi;
            for (std::size_t c = 0; c < meta.width; ++c) {
                lo += weights[c] * pair[c];
                hi += weights[c] * pair[c + meta.width];
            }
            if (lo != proof.final_codeword[query % 4] ||
                hi != proof.final_codeword[query % 4 + 4])
                return std::nullopt;
            continue;
        }
        auto index = query;
        for (std::size_t r = 0; r < mu; ++r) {
            const auto half = (meta.m * 4) >> r;
            const auto pair_index = index % half;
            Fpk lo, hi;
            if (r == 0) {
                const auto pair =
                    lookup(proof.initial, indices[0], pair_index, meta.width);
                for (std::size_t c = 0; c < meta.width; ++c) {
                    lo += weights[c] * pair[c];
                    hi += weights[c] * pair[c + meta.width];
                }
            } else {
                const auto pair =
                    lookup(proof.folded[r - 1], indices[r], pair_index, 1);
                lo = pair[0];
                hi = pair[1];
            }
            const auto folded =
                (lo + hi +
                 sumcheck.point()[r] *
                     ((lo - hi) * diagonal(mu - r, pair_index).inverse())) *
                inv2;
            Fpk expected;
            if (r + 1 == mu)
                expected = proof.final_codeword[pair_index];
            else {
                const auto childhalf = half / 2;
                const auto child = lookup(proof.folded[r], indices[r + 1],
                                          pair_index % childhalf, 1);
                expected = child[pair_index >= childhalf ? 1 : 0];
            }
            if (folded != expected)
                return std::nullopt;
            index = pair_index;
        }
    }
    return OperandReduction{sumcheck.point(),
                            proof.sumcheck.operand_evaluations};
}
std::optional<OperandReduction>
verify_blocks(const Metadata &meta, std::span<const BlockOperand> operands,
              std::span<const Fpk> weights, std::span<const Fpk> targets,
              const Proof &proof, PublicCoin &coin, CommitmentPremise premise,
              const Parameters &params) {
    if (!valid_statement(meta, operands.size(), weights, targets, premise,
                         params))
        return std::nullopt;
    for (const auto &o : operands)
        if (!valid_block_layout(o, meta.m))
            return std::nullopt;
    bind_block_operands(operands, coin);
    auto result = verify(meta, operands.size(), weights, targets, proof, coin,
                         premise, params);
    if (!result)
        return std::nullopt;
    for (std::size_t i = 0; i < operands.size(); ++i)
        if (result->operand_evaluations[i] !=
            evaluate_block_operand(operands[i], meta.m, result->point))
            return std::nullopt;
    return result;
}
} // namespace laminate::basefold::foldable
