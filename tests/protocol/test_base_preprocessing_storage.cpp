/// @file test_base_preprocessing_storage.cpp
/// @brief Integrity and ownership tests for Base preprocessing manifests.

#include "test_helpers.hpp"

#include "laminate/payload/compiler.hpp"
#include "laminate/protocol/storage/base_preprocessing.hpp"
#include "laminate/transcript/hash.hpp"

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
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::payload;
using namespace laminate::protocol;

class TemporaryDirectory {
  public:
    explicit TemporaryDirectory(std::string_view label) {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-base-preprocessing-" + std::string(label) +
                     "-" + std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(path_, error)) {
                return;
            }
        }
        throw std::runtime_error("failed to create temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

Digest identity(std::uint8_t seed) {
    Digest result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(seed + index);
    }
    return result;
}

std::span<const std::uint8_t> as_bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t *>(value.data()),
            value.size()};
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_blob(std::vector<std::uint8_t> &output,
                 std::span<const std::uint8_t> value) {
    append_u64(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

std::vector<std::uint8_t> test_bundle(bool evaluation,
                                      const Digest &bundle_identity,
                                      std::uint8_t seed) {
    constexpr std::array<std::uint8_t, 8> kEvaluationMagic{
        'L', 'M', 'S', 'E', 'A', 'L', 'E', 'V'};
    constexpr std::array<std::uint8_t, 8> kClientMagic{
        'L', 'M', 'S', 'E', 'A', 'L', 'C', 'L'};
    std::vector<std::uint8_t> output;
    const auto &magic = evaluation ? kEvaluationMagic : kClientMagic;
    output.insert(output.end(), magic.begin(), magic.end());
    output.push_back(1);
    output.push_back(0);
    const std::array<std::uint8_t, 5> descriptor{
        seed, static_cast<std::uint8_t>(seed + 1U),
        static_cast<std::uint8_t>(seed + 2U),
        static_cast<std::uint8_t>(seed + 3U),
        static_cast<std::uint8_t>(seed + 4U)};
    append_blob(output, descriptor);
    output.insert(output.end(), bundle_identity.begin(),
                  bundle_identity.end());
    const std::array<std::uint8_t, 7> public_key{
        seed, seed, seed, seed, seed, seed, seed};
    const std::array<std::uint8_t, 9> role_key{
        static_cast<std::uint8_t>(seed + 9U),
        static_cast<std::uint8_t>(seed + 8U),
        static_cast<std::uint8_t>(seed + 7U),
        static_cast<std::uint8_t>(seed + 6U),
        static_cast<std::uint8_t>(seed + 5U),
        static_cast<std::uint8_t>(seed + 4U),
        static_cast<std::uint8_t>(seed + 3U),
        static_cast<std::uint8_t>(seed + 2U),
        static_cast<std::uint8_t>(seed + 1U)};
    append_blob(output, public_key);
    append_blob(output, role_key);
    if (evaluation) {
        const std::array<std::uint8_t, 3> galois{
            static_cast<std::uint8_t>(seed + 11U),
            static_cast<std::uint8_t>(seed + 12U),
            static_cast<std::uint8_t>(seed + 13U)};
        append_blob(output, galois);
    }
    Sha256Hasher hasher;
    hasher.update(as_bytes("LaminateImpl/SealContextBundleChecksum/v1"));
    hasher.update(output);
    const Digest checksum = hasher.finish();
    output.insert(output.end(), checksum.begin(), checksum.end());
    return output;
}

void write_file(const std::filesystem::path &path,
                std::span<const std::uint8_t> bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.close();
    if (!output) {
        throw std::runtime_error("failed to write test bundle");
    }
}

void flip_byte(const std::filesystem::path &path, std::streamoff offset) {
    std::fstream file(path,
                      std::ios::binary | std::ios::in | std::ios::out);
    file.seekg(offset);
    char value = 0;
    file.read(&value, 1);
    value ^= 0x01;
    file.seekp(offset);
    file.write(&value, 1);
    file.close();
    if (!file) {
        throw std::runtime_error("failed to corrupt test file");
    }
}

PayloadCircuit test_payload(std::size_t inputs = 2) {
    PayloadBuilder builder(PayloadShape::wide(8), inputs);
    if (inputs == 2) {
        builder.set_outputs({builder.mul(0, 1)});
    } else {
        builder.set_outputs({0});
    }
    return builder.finish();
}

struct CircuitFixture {
    PayloadCircuit payload;
    LayeredCircuit layered;
    PublicSetup setup;

    explicit CircuitFixture(std::size_t inputs = 2)
        : payload(test_payload(inputs)), layered(compile(payload)),
          setup(make_direct_setup(payload, layered)) {}
};

BasePreprocessingManifestOptions options(
    const TemporaryDirectory &manifest_directory,
    const TemporaryDirectory &server_directory,
    const TemporaryDirectory &client_directory,
    std::optional<BasePreparedPlaintextCacheMetadata> cache = std::nullopt) {
    return BasePreprocessingManifestOptions{
        .manifest_directory = manifest_directory.path(),
        .evaluation_bundle_path =
            server_directory.path() / "server.bundle",
        .client_bundle_path = client_directory.path() / "client.bundle",
        .max_manifest_bytes = 1ULL << 20U,
        .max_bundle_bytes = 1ULL << 20U,
        .min_free_bytes = 1,
        .prepared_plaintext_cache = cache,
    };
}

BasePreprocessingManifestOpenLimits open_limits() {
    return BasePreprocessingManifestOpenLimits{
        .max_manifest_bytes = 1ULL << 20U,
        .max_bundle_bytes = 1ULL << 20U,
    };
}

void install_bundles(const TemporaryDirectory &directory,
                     const TemporaryDirectory &client_directory,
                     const Digest &bundle_identity,
                     const Digest *client_identity = nullptr) {
    const std::vector<std::uint8_t> evaluation =
        test_bundle(true, bundle_identity, 17);
    const std::vector<std::uint8_t> client = test_bundle(
        false, client_identity == nullptr ? bundle_identity
                                          : *client_identity,
        41);
    write_file(directory.path() / "server.bundle", evaluation);
    write_file(client_directory.path() / "client.bundle", client);
}

template <typename Body> bool throws(Body &&body) {
    try {
        std::forward<Body>(body)();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

void check_round_trip() {
    CircuitFixture fixture;
    TemporaryDirectory manifest_directory("round-trip-manifest");
    TemporaryDirectory server_directory("round-trip-server");
    TemporaryDirectory client_directory("round-trip-client");
    const Digest bundle_identity = identity(51);
    install_bundles(server_directory, client_directory, bundle_identity);
    const std::uint64_t evaluation_bytes = std::filesystem::file_size(
        server_directory.path() / "server.bundle");
    const std::uint64_t client_bytes = std::filesystem::file_size(
        client_directory.path() / "client.bundle");
    const BasePreparedPlaintextCacheMetadata cache{
        .logical_plaintexts = 2,
        .level_representations = 6,
        .ntt_coefficient_bytes = 4096,
    };

    const BasePreprocessingManifest published =
        publish_base_preprocessing_manifest(
            fixture.setup, fixture.payload, fixture.layered,
            options(manifest_directory, server_directory,
                    client_directory, cache));
    CHECK(std::filesystem::exists(manifest_directory.path() /
                                  "manifest.bin"));
    CHECK(!std::filesystem::exists(manifest_directory.path() /
                                   "manifest.partial"));
    CHECK(published.public_setup_canonical ==
          encode_canonical(fixture.setup));
    CHECK(published.public_setup_digest == setup_digest(fixture.setup));
    CHECK(published.payload_digest == digest(fixture.payload));
    CHECK(published.layered_digest == digest(fixture.layered));
    CHECK(published.circuit_digest ==
          combined_digest(fixture.payload, fixture.layered));
    CHECK(published.bundle_identity == bundle_identity);
    CHECK(published.evaluation_bundle.serialized_bytes == evaluation_bytes);
    CHECK(published.client_bundle.serialized_bytes == client_bytes);
    CHECK(published.evaluation_bundle.file_digest ==
          sha256(test_bundle(true, bundle_identity, 17)));
    CHECK(published.client_bundle.file_digest ==
          sha256(test_bundle(false, bundle_identity, 41)));
    CHECK(published.prepared_plaintext_cache == cache);
    CHECK(published.manifest_bytes ==
          std::filesystem::file_size(manifest_directory.path() /
                                     "manifest.bin"));
    CHECK(std::filesystem::file_size(server_directory.path() /
                                     "server.bundle") ==
          evaluation_bytes);
    CHECK(std::filesystem::file_size(client_directory.path() /
                                     "client.bundle") ==
          client_bytes);
    CHECK(std::distance(
              std::filesystem::directory_iterator(
                  manifest_directory.path()),
              std::filesystem::directory_iterator{}) == 1);
    CHECK(std::distance(
              std::filesystem::directory_iterator(server_directory.path()),
              std::filesystem::directory_iterator{}) == 1);
    CHECK(std::distance(
              std::filesystem::directory_iterator(client_directory.path()),
              std::filesystem::directory_iterator{}) == 1);

    const BasePreprocessingManifest reopened =
        open_base_preprocessing_manifest(
            manifest_directory.path(), fixture.setup, fixture.payload,
            fixture.layered, open_limits());
    CHECK(reopened == published);
    const OpenedBaseServerPreprocessing server =
        open_server_base_preprocessing(
            manifest_directory.path(),
            server_directory.path() / "server.bundle", fixture.setup,
            fixture.payload, fixture.layered, open_limits());
    CHECK(server.manifest == published);
    CHECK(server.evaluation_bundle_path ==
          std::filesystem::canonical(server_directory.path() /
                                     "server.bundle"));
    const OpenedBaseClientPreprocessing client =
        open_client_base_preprocessing(
            manifest_directory.path(),
            client_directory.path() / "client.bundle", fixture.setup,
            fixture.payload, fixture.layered, open_limits());
    CHECK(client.manifest == published);
    CHECK(client.client_bundle_path ==
          std::filesystem::canonical(client_directory.path() /
                                     "client.bundle"));
    CHECK(throws([&] {
        (void)publish_base_preprocessing_manifest(
            fixture.setup, fixture.payload, fixture.layered,
            options(manifest_directory, server_directory,
                    client_directory, cache));
    }));
}

void check_fail_closed_publication() {
    CircuitFixture fixture;
    const Digest server_identity = identity(71);
    const Digest client_identity = identity(99);

    TemporaryDirectory mixed_manifest("mixed-manifest");
    TemporaryDirectory mixed_server("mixed-server");
    TemporaryDirectory mixed_client("mixed-client");
    install_bundles(mixed_server, mixed_client, server_identity,
                    &client_identity);
    CHECK(throws([&] {
        (void)publish_base_preprocessing_manifest(
            fixture.setup, fixture.payload, fixture.layered,
            options(mixed_manifest, mixed_server, mixed_client));
    }));
    CHECK(!std::filesystem::exists(mixed_manifest.path() /
                                   "manifest.bin"));
    CHECK(!std::filesystem::exists(mixed_manifest.path() /
                                   "manifest.partial"));

    TemporaryDirectory corrupt_manifest("corrupt-manifest");
    TemporaryDirectory corrupt_server("corrupt-server");
    TemporaryDirectory corrupt_client("corrupt-client");
    install_bundles(corrupt_server, corrupt_client, server_identity);
    flip_byte(corrupt_server.path() / "server.bundle", 25);
    CHECK(throws([&] {
        (void)publish_base_preprocessing_manifest(
            fixture.setup, fixture.payload, fixture.layered,
            options(corrupt_manifest, corrupt_server, corrupt_client));
    }));
    CHECK(!std::filesystem::exists(corrupt_manifest.path() /
                                   "manifest.bin"));

    TemporaryDirectory bounded_manifest("bounded-manifest");
    TemporaryDirectory bounded_server("bounded-server");
    TemporaryDirectory bounded_client("bounded-client");
    install_bundles(bounded_server, bounded_client, server_identity);
    BasePreprocessingManifestOptions too_small =
        options(bounded_manifest, bounded_server, bounded_client);
    too_small.max_bundle_bytes = 1;
    CHECK(throws([&] {
        (void)publish_base_preprocessing_manifest(
            fixture.setup, fixture.payload, fixture.layered, too_small);
    }));
    CHECK(!std::filesystem::exists(bounded_manifest.path() /
                                   "manifest.bin"));
}

void check_open_rejects_drift() {
    CircuitFixture fixture;
    const Digest bundle_identity = identity(121);

    TemporaryDirectory bundle_manifest("bundle-manifest");
    TemporaryDirectory bundle_server("bundle-server");
    TemporaryDirectory bundle_client("bundle-client");
    install_bundles(bundle_server, bundle_client, bundle_identity);
    (void)publish_base_preprocessing_manifest(
        fixture.setup, fixture.payload, fixture.layered,
        options(bundle_manifest, bundle_server, bundle_client));
    flip_byte(bundle_client.path() / "client.bundle", 40);
    CHECK(!throws([&] {
        (void)open_base_preprocessing_manifest(
            bundle_manifest.path(), fixture.setup, fixture.payload,
            fixture.layered, open_limits());
    }));
    CHECK(throws([&] {
        (void)open_client_base_preprocessing(
            bundle_manifest.path(),
            bundle_client.path() / "client.bundle", fixture.setup,
            fixture.payload, fixture.layered, open_limits());
    }));

    TemporaryDirectory setup_manifest("setup-manifest");
    TemporaryDirectory setup_server("setup-server");
    TemporaryDirectory setup_client("setup-client");
    install_bundles(setup_server, setup_client, bundle_identity);
    (void)publish_base_preprocessing_manifest(
        fixture.setup, fixture.payload, fixture.layered,
        options(setup_manifest, setup_server, setup_client));
    CircuitFixture other(1);
    CHECK(throws([&] {
        (void)open_base_preprocessing_manifest(
            setup_manifest.path(), other.setup, other.payload, other.layered,
            open_limits());
    }));

    TemporaryDirectory manifest_directory("manifest-drift");
    TemporaryDirectory manifest_server("manifest-server");
    TemporaryDirectory manifest_client("manifest-client");
    install_bundles(manifest_server, manifest_client, bundle_identity);
    (void)publish_base_preprocessing_manifest(
        fixture.setup, fixture.payload, fixture.layered,
        options(manifest_directory, manifest_server, manifest_client));
    flip_byte(manifest_directory.path() / "manifest.bin", 20);
    CHECK(throws([&] {
        (void)open_base_preprocessing_manifest(
            manifest_directory.path(), fixture.setup, fixture.payload,
            fixture.layered, open_limits());
    }));
}

void check_role_openers_are_disjoint() {
    CircuitFixture fixture;
    const Digest bundle_identity = identity(151);

    TemporaryDirectory server_manifest("server-only-manifest");
    TemporaryDirectory server_directory("server-only-server");
    TemporaryDirectory discarded_client("server-only-client");
    install_bundles(server_directory, discarded_client, bundle_identity);
    (void)publish_base_preprocessing_manifest(
        fixture.setup, fixture.payload, fixture.layered,
        options(server_manifest, server_directory, discarded_client));
    std::filesystem::remove_all(discarded_client.path());
    const OpenedBaseServerPreprocessing server =
        open_server_base_preprocessing(
            server_manifest.path(),
            server_directory.path() / "server.bundle", fixture.setup,
            fixture.payload, fixture.layered, open_limits());
    CHECK(server.manifest.bundle_identity == bundle_identity);

    TemporaryDirectory client_manifest("client-only-manifest");
    TemporaryDirectory discarded_server("client-only-server");
    TemporaryDirectory client_directory("client-only-client");
    install_bundles(discarded_server, client_directory, bundle_identity);
    (void)publish_base_preprocessing_manifest(
        fixture.setup, fixture.payload, fixture.layered,
        options(client_manifest, discarded_server, client_directory));
    std::filesystem::remove_all(discarded_server.path());
    const OpenedBaseClientPreprocessing client =
        open_client_base_preprocessing(
            client_manifest.path(),
            client_directory.path() / "client.bundle", fixture.setup,
            fixture.payload, fixture.layered, open_limits());
    CHECK(client.manifest.bundle_identity == bundle_identity);
}

} // namespace

int main() {
    laminate::test::Runner runner("Base preprocessing storage");
    runner.run("publishes and reopens exact manifest bindings",
               check_round_trip);
    runner.run("fails before manifest-last publication",
               check_fail_closed_publication);
    runner.run("rejects bundle, setup, and manifest drift",
               check_open_rejects_drift);
    runner.run("role openers never require the other role directory",
               check_role_openers_are_disjoint);
    return runner.summary();
}
