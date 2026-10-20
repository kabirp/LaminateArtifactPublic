#include "test_helpers.hpp"

#include "laminate/storage/native_field_artifact.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using laminate::Digest;
using laminate::Fq;
using laminate::Fq2;
using laminate::storage::NativeFieldArtifact;
using laminate::storage::NativeFieldArtifactOptions;
using laminate::storage::NativeFieldArtifactWriter;
using laminate::storage::NativeFieldArrayLayout;
using laminate::storage::NativeFieldElementKind;
using laminate::storage::native_field_artifact_physical_bytes;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-native-field-" + std::to_string(stamp) +
                     "-" + std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create a temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

class CurrentPathGuard {
  public:
    CurrentPathGuard() : original_(std::filesystem::current_path()) {}
    ~CurrentPathGuard() {
        std::error_code ignored;
        std::filesystem::current_path(original_, ignored);
    }

    const std::filesystem::path &original() const { return original_; }

  private:
    std::filesystem::path original_;
};

bool throws_exception(const auto &body) {
    try {
        body();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

std::vector<std::uint8_t> bytes(std::string_view value) {
    return {value.begin(), value.end()};
}

Digest artifact_identity() {
    return laminate::sha256(bytes("Laminate native-field artifact test"));
}

NativeFieldArtifactOptions options(
    std::uint64_t max_total_bytes = 1ULL << 20U) {
    return NativeFieldArtifactOptions{
        .max_total_bytes = max_total_bytes,
        .min_free_bytes = 1,
    };
}

std::uint64_t directory_bytes(const std::filesystem::path &directory) {
    std::uint64_t result = 0;
    for (const auto &entry :
         std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            result += entry.file_size();
        }
    }
    return result;
}

std::filesystem::path first_array_path(
    const std::filesystem::path &directory) {
    return directory / "array-0000000000000000.bin";
}

laminate::storage::NativeFieldArtifactWriteResult write_fixture(
    const std::filesystem::path &directory) {
    const std::array<Fq, 4> base{Fq(1), Fq(2), Fq(3), Fq(5)};
    const std::array<Fq2, 3> extension{
        Fq2({Fq(7), Fq(11)}),
        Fq2({Fq(13), Fq(17)}),
        Fq2({Fq(19), Fq(23)}),
    };
    std::array<laminate::basefold::Digest, 2> digests{};
    for (std::size_t byte = 0; byte < digests[0].size(); ++byte) {
        digests[0][byte] = static_cast<std::uint8_t>(byte);
        digests[1][byte] = static_cast<std::uint8_t>(byte + 40);
    }

    NativeFieldArtifactWriter writer(directory, options(),
                                     artifact_identity());
    writer.begin_array("message", NativeFieldElementKind::Fq, base.size());
    writer.append(std::span(base).first(1));
    writer.append(std::span(base).subspan(1));
    writer.finish_array();
    writer.begin_array("folded", NativeFieldElementKind::Fq2,
                       extension.size());
    writer.append(extension);
    writer.finish_array();
    writer.begin_array("merkle-level", NativeFieldElementKind::BaseFoldDigest,
                       digests.size());
    writer.append(digests);
    writer.finish_array();
    return writer.finish();
}

void test_reopen_and_typed_ranges() {
    TemporaryDirectory directory;
    const auto result = write_fixture(directory.path());
    const std::array<NativeFieldArrayLayout, 3> layout{{
        {"message", NativeFieldElementKind::Fq, 4},
        {"folded", NativeFieldElementKind::Fq2, 3},
        {"merkle-level", NativeFieldElementKind::BaseFoldDigest, 2},
    }};
    CHECK(native_field_artifact_physical_bytes(layout) ==
          result.physical_bytes);
    CHECK(result.identity == artifact_identity());
    CHECK(result.arrays.size() == 3);
    CHECK(result.physical_bytes == directory_bytes(directory.path()));

    const NativeFieldArtifact artifact =
        NativeFieldArtifact::open(directory.path(), artifact_identity());
    CHECK(artifact.identity() == artifact_identity());
    CHECK(artifact.physical_bytes() == result.physical_bytes);
    CHECK(artifact.arrays() == result.arrays);
    CHECK(artifact.array("folded").kind == NativeFieldElementKind::Fq2);

    auto message = artifact.open_array("message");
    std::array<Fq, 2> first{};
    CHECK(message.read(first) == first.size());
    CHECK((first == std::array<Fq, 2>{Fq(1), Fq(2)}));
    message.seek(3);
    std::array<Fq, 2> tail{};
    CHECK(message.read(tail) == 1);
    CHECK(tail[0] == Fq(5));
    CHECK(message.position() == message.size());
    message.rewind();
    CHECK(message.position() == 0);

    auto folded = artifact.open_array("folded");
    std::array<Fq2, 3> extension{};
    CHECK(folded.read(extension) == extension.size());
    CHECK(extension[1] == Fq2({Fq(13), Fq(17)}));
    CHECK(throws_exception([&] {
        std::array<Fq, 1> wrong_type{};
        (void)folded.read(wrong_type);
    }));

    auto merkle = artifact.open_array("merkle-level");
    std::array<laminate::basefold::Digest, 2> digests{};
    CHECK(merkle.read(digests) == digests.size());
    CHECK(digests[0][7] == 7);
    CHECK(digests[1][7] == 47);
}

void test_incremental_hash_matches_one_shot() {
    for (std::size_t length = 0; length <= 130; ++length) {
        std::vector<std::uint8_t> input(length);
        for (std::size_t index = 0; index < input.size(); ++index) {
            input[index] = static_cast<std::uint8_t>(17 * index + length);
        }
        laminate::Sha256Hasher hasher;
        std::size_t offset = 0;
        for (std::size_t chunk : {3U, 61U, 1U, 64U, 7U}) {
            const std::size_t count =
                std::min(chunk, input.size() - offset);
            hasher.update(std::span(input).subspan(offset, count));
            offset += count;
            if (offset == input.size()) {
                break;
            }
        }
        if (offset != input.size()) {
            hasher.update(std::span(input).subspan(offset));
        }
        CHECK(hasher.finish() == laminate::sha256(input));
    }
}

void test_writer_cleanup_and_stable_paths() {
    TemporaryDirectory root;
    const std::filesystem::path first = root.path() / "first";
    const std::filesystem::path second = root.path() / "second";
    const std::filesystem::path stable = root.path() / "stable";
    std::filesystem::create_directory(first);
    std::filesystem::create_directory(second);
    std::filesystem::create_directory(stable);

    {
        NativeFieldArtifactWriter abandoned(first, options(),
                                            artifact_identity());
        abandoned.begin_array("unfinished", NativeFieldElementKind::Fq, 2);
        const std::array<Fq, 1> prefix{Fq(1)};
        abandoned.append(prefix);
    }
    CHECK(std::filesystem::is_empty(first));

    NativeFieldArtifactWriter destination(first, options(),
                                          artifact_identity());
    destination.begin_array("unfinished", NativeFieldElementKind::Fq, 2);
    const std::array<Fq, 1> prefix{Fq(1)};
    destination.append(prefix);
    NativeFieldArtifactWriter source(second, options(), artifact_identity());
    destination = std::move(source);
    CHECK(std::filesystem::is_empty(first));

    CurrentPathGuard current_path;
    std::filesystem::current_path(root.path());
    NativeFieldArtifactWriter writer("stable", options(),
                                     artifact_identity());
    std::filesystem::current_path(current_path.original());
    const std::array<Fq, 1> value{Fq(9)};
    writer.begin_array("value", NativeFieldElementKind::Fq, value.size());
    writer.append(value);
    writer.finish_array();
    const auto written = writer.finish();
    CHECK(std::filesystem::equivalent(written.directory, stable));

    std::filesystem::current_path(root.path());
    const NativeFieldArtifact artifact =
        NativeFieldArtifact::open("stable", artifact_identity());
    std::filesystem::current_path(current_path.original());
    auto reader = artifact.open_array("value");
    std::array<Fq, 1> reopened{};
    CHECK(reader.read(reopened) == 1);
    CHECK(reopened == value);
}

void test_identity_mismatch_is_rejected() {
    TemporaryDirectory directory;
    (void)write_fixture(directory.path());
    const Digest wrong = laminate::sha256(bytes("wrong artifact"));
    CHECK(throws_exception([&] {
        (void)NativeFieldArtifact::open(directory.path(), wrong);
    }));
}

void test_corruption_and_truncation_are_rejected() {
    {
        TemporaryDirectory directory;
        (void)write_fixture(directory.path());
        std::fstream array(first_array_path(directory.path()),
                           std::ios::binary | std::ios::in | std::ios::out);
        array.seekg(-1, std::ios::end);
        char byte = 0;
        array.read(&byte, 1);
        byte ^= 1;
        array.clear();
        array.seekp(-1, std::ios::end);
        array.write(&byte, 1);
        array.close();
        CHECK(throws_exception([&] {
            (void)NativeFieldArtifact::open(directory.path(),
                                            artifact_identity());
        }));
    }
    {
        TemporaryDirectory directory;
        (void)write_fixture(directory.path());
        const auto path = first_array_path(directory.path());
        std::filesystem::resize_file(path,
                                     std::filesystem::file_size(path) - 1);
        CHECK(throws_exception([&] {
            (void)NativeFieldArtifact::open(directory.path(),
                                            artifact_identity());
        }));
    }
}

void test_trailing_data_is_rejected() {
    {
        TemporaryDirectory directory;
        (void)write_fixture(directory.path());
        std::ofstream output(first_array_path(directory.path()),
                             std::ios::binary | std::ios::app);
        output.put('\0');
        output.close();
        CHECK(throws_exception([&] {
            (void)NativeFieldArtifact::open(directory.path(),
                                            artifact_identity());
        }));
    }
    {
        TemporaryDirectory directory;
        (void)write_fixture(directory.path());
        std::ofstream output(directory.path() / "manifest.bin",
                             std::ios::binary | std::ios::app);
        output.put('\0');
        output.close();
        CHECK(throws_exception([&] {
            (void)NativeFieldArtifact::open(directory.path(),
                                            artifact_identity());
        }));
    }
}

void test_quota_failure_never_publishes_manifest() {
    TemporaryDirectory directory;
    NativeFieldArtifactWriter writer(directory.path(), options(96),
                                     artifact_identity());
    CHECK(throws_exception([&] {
        writer.begin_array("message", NativeFieldElementKind::Fq, 1);
    }));
    CHECK(!std::filesystem::exists(directory.path() / "manifest.bin"));
    CHECK(std::filesystem::is_empty(directory.path()));
}

void test_positional_fq_array_is_standard_and_validated() {
    TemporaryDirectory directory;
    const std::array<Fq, 8> expected{
        Fq(2), Fq(3), Fq(5), Fq(7),
        Fq(11), Fq(13), Fq(17), Fq(19),
    };
    NativeFieldArtifactWriter writer(directory.path(), options(),
                                     artifact_identity());
    writer.begin_positional_fq_array("permuted", expected.size());
    writer.write_fq_at(4, std::span(expected).subspan(4));
    writer.write_fq_at(0, std::span(expected).first(2));
    writer.write_fq_at(2, std::span(expected).subspan(2, 2));
    writer.finish_array();
    const auto written = writer.finish();
    CHECK(written.physical_bytes == directory_bytes(directory.path()));
    CHECK(written.positional_publication_read_bytes ==
          written.arrays.front().physical_bytes);
    CHECK(written.positional_publication_read_operations == 1);

    const NativeFieldArtifact reopened =
        NativeFieldArtifact::open(directory.path(), artifact_identity());
    auto reader = reopened.open_array("permuted");
    std::array<Fq, 8> values{};
    CHECK(reader.read(values) == values.size());
    CHECK(values == expected);

    TemporaryDirectory overlap;
    NativeFieldArtifactWriter overlap_writer(
        overlap.path(), options(), artifact_identity());
    overlap_writer.begin_positional_fq_array("overlap", 4);
    overlap_writer.write_fq_at(0, std::span(expected).first(2));
    CHECK(throws_exception([&] {
        overlap_writer.write_fq_at(1,
                                   std::span(expected).subspan(1, 2));
    }));
    overlap_writer.write_fq_at(2, std::span(expected).subspan(2, 2));
    overlap_writer.finish_array();
    (void)overlap_writer.finish();

    TemporaryDirectory hole;
    {
        NativeFieldArtifactWriter hole_writer(
            hole.path(), options(), artifact_identity());
        hole_writer.begin_positional_fq_array("hole", 4);
        hole_writer.write_fq_at(0, std::span(expected).first(2));
        hole_writer.write_fq_at(3, std::span(expected).subspan(3, 1));
        CHECK(throws_exception([&] { hole_writer.finish_array(); }));
    }
    CHECK(std::filesystem::is_empty(hole.path()));

    TemporaryDirectory incomplete;
    {
        NativeFieldArtifactWriter abandoned(
            incomplete.path(), options(), artifact_identity());
        abandoned.begin_positional_fq_array("incomplete", 4);
        abandoned.write_fq_at(2, std::span(expected).first(2));
    }
    CHECK(std::filesystem::is_empty(incomplete.path()));
}

void test_buffered_bulk_reads_and_trusted_writer_transition() {
    TemporaryDirectory directory;
    constexpr std::size_t kFqCount = 10'003;
    constexpr std::size_t kFq2Count = 5'003;
    constexpr std::size_t kDigestCount = 2'053;
    std::vector<Fq> fq(kFqCount);
    std::vector<Fq2> fq2(kFq2Count);
    std::vector<laminate::basefold::Digest> digests(kDigestCount);
    for (std::size_t index = 0; index < fq.size(); ++index) {
        fq[index] = Fq(17U * index + 3U);
    }
    for (std::size_t index = 0; index < fq2.size(); ++index) {
        fq2[index] = Fq2({Fq(19U * index + 5U),
                          Fq(23U * index + 7U)});
    }
    for (std::size_t index = 0; index < digests.size(); ++index) {
        for (std::size_t byte = 0; byte < digests[index].size(); ++byte) {
            digests[index][byte] = static_cast<std::uint8_t>(index + byte);
        }
    }

    NativeFieldArtifactWriter writer(
        directory.path(), options(1ULL << 22U), artifact_identity());
    writer.begin_array("fq-bulk", NativeFieldElementKind::Fq, fq.size());
    writer.append(fq);
    writer.finish_array();
    writer.begin_array("fq2-bulk", NativeFieldElementKind::Fq2,
                       fq2.size());
    writer.append(fq2);
    writer.finish_array();
    writer.begin_array("digest-bulk",
                       NativeFieldElementKind::BaseFoldDigest,
                       digests.size());
    writer.append(digests);
    writer.finish_array();
    CHECK(throws_exception(
        [&] { (void)writer.trusted_finished_artifact(); }));
    const auto written = writer.finish();
    const NativeFieldArtifact trusted = writer.trusted_finished_artifact();
    CHECK(trusted.arrays() == written.arrays);
    CHECK(trusted.physical_bytes() == written.physical_bytes);

    auto fq_reader = trusted.open_array("fq-bulk");
    std::vector<Fq> fq_read(fq.size());
    CHECK(fq_reader.read(fq_read) == fq_read.size());
    CHECK(fq_read == fq);
    fq_reader.seek(8'190);
    std::array<Fq, 7> fq_boundary{};
    CHECK(fq_reader.read(fq_boundary) == fq_boundary.size());
    CHECK(std::equal(fq_boundary.begin(), fq_boundary.end(),
                     fq.begin() + 8'190));

    auto fq2_reader = trusted.open_array("fq2-bulk");
    std::vector<Fq2> fq2_read(fq2.size());
    CHECK(fq2_reader.read(fq2_read) == fq2_read.size());
    CHECK(fq2_read == fq2);
    auto digest_reader = trusted.open_array("digest-bulk");
    std::vector<laminate::basefold::Digest> digest_read(digests.size());
    CHECK(digest_reader.read(digest_read) == digest_read.size());
    CHECK(digest_read == digests);

    const NativeFieldArtifact reopened = NativeFieldArtifact::open(
        directory.path(), artifact_identity());
    CHECK(reopened.arrays() == trusted.arrays());

    std::fstream changed(first_array_path(directory.path()),
                         std::ios::binary | std::ios::in | std::ios::out);
    CHECK(static_cast<bool>(changed));
    changed.seekg(-1, std::ios::end);
    char byte = 0;
    changed.read(&byte, 1);
    changed.seekp(-1, std::ios::end);
    byte ^= 1;
    changed.write(&byte, 1);
    changed.close();
    CHECK(throws_exception([&] {
        (void)NativeFieldArtifact::open(directory.path(),
                                        artifact_identity());
    }));
}

} // namespace

int main() {
    laminate::test::Runner runner("native-field artifact store");
    runner.run("reopen and typed ranges", test_reopen_and_typed_ranges);
    runner.run("incremental SHA-256", test_incremental_hash_matches_one_shot);
    runner.run("writer cleanup and stable paths",
               test_writer_cleanup_and_stable_paths);
    runner.run("identity mismatch", test_identity_mismatch_is_rejected);
    runner.run("corruption and truncation",
               test_corruption_and_truncation_are_rejected);
    runner.run("trailing data", test_trailing_data_is_rejected);
    runner.run("quota leaves no manifest",
               test_quota_failure_never_publishes_manifest);
    runner.run("positional Fq arrays",
               test_positional_fq_array_is_standard_and_validated);
    runner.run("buffered bulk reads and trusted writer transition",
               test_buffered_bulk_reads_and_trusted_writer_transition);
    return runner.summary();
}
