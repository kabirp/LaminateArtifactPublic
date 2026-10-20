/// @file test_packed_preprocessing_storage.cpp
/// @brief Ownership, relocation, and fail-closed tests for packed setup.

#include "test_helpers.hpp"

#include "laminate/payload/compiler.hpp"
#include "laminate/gates/canonical_tables.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/protocol/storage/packed_preprocessing.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
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
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-packed-preprocessing-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(path_, error)) {
                return;
            }
        }
        throw std::runtime_error("failed to create test directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

template <typename Body> bool throws(Body &&body) {
    try {
        body();
        return false;
    } catch (const std::exception &) {
        return true;
    }
}

Digest identity(std::uint8_t seed) {
    Digest result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(seed + index);
    }
    return result;
}

void write_file(const std::filesystem::path &path,
                std::string_view value) {
    std::ofstream output(path, std::ios::binary | std::ios::out);
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    output.close();
    if (!output) {
        throw std::runtime_error("failed to write test artifact");
    }
}

void write_repeated_file(const std::filesystem::path &path,
                         std::uint64_t size) {
    std::ofstream output(path, std::ios::binary | std::ios::out);
    std::vector<char> block(64ULL << 10U);
    for (std::size_t index = 0; index < block.size(); ++index) {
        block[index] = static_cast<char>((index * 29U + 7U) & 0xffU);
    }
    std::uint64_t written = 0;
    while (written < size) {
        const std::size_t count = static_cast<std::size_t>(
            std::min<std::uint64_t>(size - written, block.size()));
        output.write(block.data(), static_cast<std::streamsize>(count));
        written += count;
    }
    output.close();
    if (!output) {
        throw std::runtime_error("failed to write large test artifact");
    }
}

std::vector<std::uint8_t> read_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

PayloadCircuit test_payload() {
    PayloadBuilder builder(PayloadShape::laned(4, 16), 2);
    const std::size_t constant = builder.add_scalar_plaintext(Fp(7));
    const WireId sum = builder.add(0, 1);
    const WireId scaled = builder.mul_plain(sum, constant);
    builder.set_outputs({scaled});
    return builder.finish();
}

CertifiedPackedWorkloadStatic test_workload() {
    PayloadCircuit payload = test_payload();
    LayeredCircuit layered = compile(payload);
    PublicSetup setup = make_direct_setup(payload, layered);
    return certify_packed_workload_static(
        std::move(payload), std::move(layered), std::move(setup));
}

CertifiedPackedWorkloadStatic quick_folded_workload() {
    PayloadCircuit payload = make_payload_circuit(WorkloadSpec{
        .kind = WorkloadKind::Diamond,
        .shape = PayloadShape::wide(32),
        .multiplicative_depth = 6,
        .width = 1'024,
        .seed = 1,
        .input_count = 64,
    });
    LayeredCircuit layered = compile(payload);
    PublicSetup setup = make_direct_setup(payload, layered);
    return certify_packed_workload_static(
        std::move(payload), std::move(layered), std::move(setup));
}

PackedPreprocessingPublishLimits publish_limits() {
    return PackedPreprocessingPublishLimits{
        .max_workload_bytes = 1ULL << 22U,
        .max_role_artifact_bytes = 1ULL << 20U,
        .max_manifest_bytes = 1ULL << 20U,
        .min_free_bytes = 1,
        .max_artifact_tree_files = 128,
        .max_artifact_tree_directories = 64,
        .max_artifact_tree_depth = 8,
        .max_artifact_tree_relative_path_bytes = 256,
        .max_artifact_tree_file_bytes = 1ULL << 26U,
        .max_artifact_tree_bytes = 1ULL << 28U,
        .workload_decode = PackedWorkloadStaticDecodeLimits{
            .max_artifact_bytes = 1ULL << 22U,
            .max_slots = 64,
            .max_payload_plaintexts = 64,
            .max_payload_gates = 256,
            .max_payload_outputs = 64,
            .max_layers = 64,
            .max_layer_gates = 1024,
            .max_affine_terms = 4096,
            .max_storage_entries = 8192,
            .max_gate_tables = 128,
        }};
}

PackedPreprocessingOpenLimits open_limits() {
    const auto publish = publish_limits();
    return PackedPreprocessingOpenLimits{
        .max_workload_bytes = publish.max_workload_bytes,
        .max_role_artifact_bytes = publish.max_role_artifact_bytes,
        .max_manifest_bytes = publish.max_manifest_bytes,
        .max_artifact_tree_files = publish.max_artifact_tree_files,
        .max_artifact_tree_directories =
            publish.max_artifact_tree_directories,
        .max_artifact_tree_depth = publish.max_artifact_tree_depth,
        .max_artifact_tree_relative_path_bytes =
            publish.max_artifact_tree_relative_path_bytes,
        .max_artifact_tree_file_bytes =
            publish.max_artifact_tree_file_bytes,
        .max_artifact_tree_bytes = publish.max_artifact_tree_bytes,
        .workload_decode = publish.workload_decode};
}

struct PublishedTree {
    CertifiedPackedWorkloadStatic workload;
    std::filesystem::path tree;
    std::filesystem::path shared;
    std::filesystem::path server;
    std::filesystem::path client;
    PackedRootManifest root;
};

PublishedTree publish_tree(const std::filesystem::path &parent,
                           std::string_view name,
                           std::string_view server_bytes =
                               "server-public-static-v1",
                           std::string_view client_bytes =
                               "client-private-static-v1",
                           std::string_view tensor_bytes =
                               "canonical-packing-tensor",
                           Digest server_tree_semantic = identity(18)) {
    const std::filesystem::path tree = parent / std::string(name);
    const std::filesystem::path shared = tree / "shared";
    const std::filesystem::path server = tree / "server";
    const std::filesystem::path client = tree / "client";
    std::filesystem::create_directories(shared);
    std::filesystem::create_directories(
        server / kPackedRoleArtifactTreeDirectory);
    std::filesystem::create_directories(
        client / kPackedRoleArtifactTreeDirectory);
    const auto server_tree =
        server / kPackedRoleArtifactTreeDirectory;
    std::filesystem::create_directories(server_tree / "basefold" /
                                        "state-0");
    std::filesystem::create_directories(server_tree / "empty");
    std::filesystem::create_directories(server_tree / "tensors");
    write_file(server_tree / "basefold" / "state-0" / "tree.bin",
               "basefold-tree-state");
    write_file(server_tree / "tensors" / "packing.bin", tensor_bytes);
    CertifiedPackedWorkloadStatic workload = test_workload();
    const auto limits = publish_limits();
    (void)publish_packed_workload_static_file(shared, workload, limits);
    write_file(server / kPackedRoleStaticFilename, server_bytes);
    write_file(client / kPackedRoleStaticFilename, client_bytes);
    (void)publish_packed_role_manifest(
        server, PackedPreprocessingRole::Server,
        workload.semantic_identity(), identity(17), server_tree_semantic,
        limits);
    (void)publish_packed_role_manifest(
        client, PackedPreprocessingRole::Client,
        workload.semantic_identity(), identity(91), identity(92), limits);
    PackedRootManifest root = publish_packed_preprocessing_root(
        shared, server, client, workload, limits);
    return PublishedTree{std::move(workload), tree, shared, server, client,
                         std::move(root)};
}

void check_shared_wide_index_codec() {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const auto mask = builder.add_plaintext(
        {Fp(2), Fp(3), Fp(5), Fp(7), Fp(11), Fp(13), Fp(17), Fp(19)});
    const auto rotated = builder.rotate(0, 3);
    builder.set_outputs({builder.add(builder.mul(rotated, 1), builder.mul_plain(0, mask))});
    auto payload = builder.finish();
    auto layered = compile(payload);
    const auto index = gates::preprocess_gate_tables(layered, gates::GateTableSet::Wide);
    auto setup = make_outsourced_gate_setup(payload, layered, index.verifier);
    const auto workload = certify_packed_workload_static(
        std::move(payload), std::move(layered), std::move(setup));
    const auto bytes = encode_packed_workload_static(workload);
    const auto limits = packed_workload_static_decode_requirements(workload, bytes.size());
    const auto restored = decode_authenticated_packed_workload_static(
        bytes, sha256(bytes), workload.semantic_identity(), limits);
    CHECK(restored.public_setup().outsourced_gate_mle == index.verifier);
    CHECK(encode_packed_workload_static(restored) == bytes);
    CHECK(limits.max_storage_entries >= index.verifier.wide_public_commitment->m);
    auto too_small = limits;
    too_small.max_storage_entries = index.verifier.wide_public_commitment->m - 1;
    CHECK(throws([&] {
        (void)decode_authenticated_packed_workload_static(
            bytes, sha256(bytes), workload.semantic_identity(), too_small);
    }));
}

void check_workload_codec_and_shared_decoder() {
    const CertifiedPackedWorkloadStatic workload = test_workload();
    const std::vector<std::uint8_t> encoded =
        encode_packed_workload_static(workload);
    const auto limits = publish_limits().workload_decode;
    const auto restored = decode_authenticated_packed_workload_static(
        encoded, sha256(encoded), workload.semantic_identity(), limits);
    CHECK(restored.payload_digest() == workload.payload_digest());
    CHECK(restored.layered_digest() == workload.layered_digest());
    CHECK(restored.circuit_digest() == workload.circuit_digest());
    CHECK(restored.setup_digest() == workload.setup_digest());
    CHECK(restored.output_dimensions() == workload.output_dimensions());
    CHECK(restored.trace_layout() == workload.trace_layout());
    CHECK(encode_packed_workload_static(restored) == encoded);

    const auto payload_bytes = encode_canonical(workload.payload());
    const auto layered_bytes = encode_canonical(workload.circuit());
    const CircuitDecodeLimits circuit_limits{
        .max_encoded_bytes = 1ULL << 20U,
        .max_slots = 64,
        .max_plaintexts = 64,
        .max_payload_inputs = 64,
        .max_payload_gates = 256,
        .max_payload_outputs = 64,
        .max_layers = 64,
        .max_layer_gates = 1024,
        .max_affine_terms = 4096,
    };
    CHECK(encode_canonical(decode_canonical_payload(
              payload_bytes, circuit_limits)) == payload_bytes);
    CHECK(encode_canonical(decode_canonical_layered(
              layered_bytes, circuit_limits)) == layered_bytes);
    auto noncanonical = payload_bytes;
    noncanonical.push_back(0);
    CHECK(throws([&] {
        (void)decode_canonical_payload(noncanonical, circuit_limits);
    }));

    PayloadBuilder no_plaintext_builder(PayloadShape::laned(4, 16), 2);
    no_plaintext_builder.set_outputs(
        {no_plaintext_builder.mul(0, 1)});
    const PayloadCircuit no_plaintext = no_plaintext_builder.finish();
    auto zero_plaintext_limit = circuit_limits;
    zero_plaintext_limit.max_plaintexts = 0;
    CHECK(encode_canonical(decode_canonical_payload(
              encode_canonical(no_plaintext), zero_plaintext_limit)) ==
          encode_canonical(no_plaintext));
    CHECK(throws([&] {
        (void)decode_canonical_payload(payload_bytes,
                                       zero_plaintext_limit);
    }));

    auto corrupted = encoded;
    corrupted.back() ^= 1U;
    CHECK(throws([&] {
        (void)decode_authenticated_packed_workload_static(
            corrupted, sha256(corrupted), workload.semantic_identity(),
            limits);
    }));
    auto too_small = limits;
    too_small.max_artifact_bytes = encoded.size() - 1U;
    CHECK(throws([&] {
        (void)decode_authenticated_packed_workload_static(
            encoded, sha256(encoded), workload.semantic_identity(),
            too_small);
    }));
}

void check_exact_quick_workload_decode_requirements() {
    const CertifiedPackedWorkloadStatic workload =
        quick_folded_workload();
    const std::vector<std::uint8_t> encoded =
        encode_packed_workload_static(workload);
    const PackedWorkloadStaticDecodeLimits requirements =
        packed_workload_static_decode_requirements(workload,
                                                   encoded.size());

    CHECK(requirements.max_artifact_bytes == encoded.size());
    CHECK(requirements.max_slots == 32);
    // Retained local nodes contribute their primitive edges as well as the
    // final output copies: six stages of 3,072 terms and the 2,047-term
    // terminal reduction. Distinct authored affine nodes remain distinct.
    CHECK(requirements.max_affine_terms == 20'479);
    CHECK(requirements.max_storage_entries == 36'034);
    CHECK(requirements.max_layer_gates == 2'048);
    const auto &input_affine = std::get<AffineLayer>(
        workload.circuit().layers[12]);
    CHECK(input_affine.intermediate_gates.size() == 1'024);
    CHECK(input_affine.gates.size() == 2'048);
    CHECK(requirements.max_layer_gates >=
          layer_dimensions(workload.circuit().layers[13]).padded_size +
              input_affine.intermediate_gates.size());
    const auto restored = decode_authenticated_packed_workload_static(
        encoded, sha256(encoded), workload.semantic_identity(),
        requirements);
    CHECK(restored.semantic_identity() == workload.semantic_identity());

    using LimitMember =
        std::size_t PackedWorkloadStaticDecodeLimits::*;
    constexpr std::array<LimitMember, 10> limit_members{
        &PackedWorkloadStaticDecodeLimits::max_artifact_bytes,
        &PackedWorkloadStaticDecodeLimits::max_slots,
        &PackedWorkloadStaticDecodeLimits::max_payload_plaintexts,
        &PackedWorkloadStaticDecodeLimits::max_payload_gates,
        &PackedWorkloadStaticDecodeLimits::max_payload_outputs,
        &PackedWorkloadStaticDecodeLimits::max_layers,
        &PackedWorkloadStaticDecodeLimits::max_layer_gates,
        &PackedWorkloadStaticDecodeLimits::max_affine_terms,
        &PackedWorkloadStaticDecodeLimits::max_storage_entries,
        &PackedWorkloadStaticDecodeLimits::max_gate_tables,
    };
    for (const LimitMember member : limit_members) {
        PackedWorkloadStaticDecodeLimits one_less = requirements;
        CHECK(one_less.*member != 0);
        --(one_less.*member);
        CHECK(throws([&] {
            (void)decode_authenticated_packed_workload_static(
                encoded, sha256(encoded), workload.semantic_identity(),
                one_less);
        }));
    }
    CHECK(throws([&] {
        (void)packed_workload_static_decode_requirements(workload, 0);
    }));

    TemporaryDirectory temporary;
    const std::filesystem::path shared = temporary.path() / "shared";
    std::filesystem::create_directory(shared);
    auto publication = publish_limits();
    publication.max_workload_bytes = encoded.size();
    publication.workload_decode = requirements;
    --publication.workload_decode.max_affine_terms;
    CHECK(throws([&] {
        (void)publish_packed_workload_static_file(
            shared, workload, publication);
    }));
    CHECK(std::filesystem::is_empty(shared));
}

void check_round_trip_and_role_separation() {
    TemporaryDirectory temporary;
    PublishedTree tree = publish_tree(temporary.path(), "tree");
    const auto limits = open_limits();
    const auto root = open_packed_preprocessing_root(
        tree.shared, tree.root.storage_identity, limits);
    CHECK(root.manifest.semantic_identity == tree.root.semantic_identity);
    CHECK(root.workload.semantic_identity() ==
          tree.workload.semantic_identity());
    const auto server = open_packed_server_preprocessing(
        tree.shared, tree.server, tree.root.storage_identity, limits);
    CHECK(server.role.role == PackedPreprocessingRole::Server);
    CHECK(server.role_artifact_path.filename() ==
          kPackedRoleStaticFilename);
    CHECK(server.artifact_tree_path.filename() ==
          kPackedRoleArtifactTreeDirectory);
    CHECK(server.role.artifact_tree.file_count == 2);
    CHECK(server.role.artifact_tree.directory_count == 4);
    CHECK(server.role.artifact_tree.entries.size() == 6);
    CHECK(server.role.artifact_tree.entries.front().relative_path ==
          "basefold");
    CHECK(server.role.artifact_tree.entries.back().relative_path ==
          "tensors/packing.bin");

    const std::filesystem::path hidden_client =
        tree.tree / "client-not-provided";
    std::filesystem::rename(tree.client, hidden_client);
    const auto server_without_client_path =
        open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity, limits);
    CHECK(server_without_client_path.role.role ==
          PackedPreprocessingRole::Server);
}

void check_relocation_preserves_identities() {
    TemporaryDirectory temporary;
    PublishedTree tree = publish_tree(temporary.path(), "before");
    const Digest semantic = tree.root.semantic_identity;
    const Digest storage = tree.root.storage_identity;
    const std::filesystem::path relocated = temporary.path() / "after";
    std::filesystem::rename(tree.tree, relocated);
    const auto opened = open_packed_client_preprocessing(
        relocated / "shared", relocated / "client", storage,
        open_limits());
    CHECK(opened.root.semantic_identity == semantic);
    CHECK(opened.root.storage_identity == storage);
    CHECK(opened.root.shared_directory ==
          std::filesystem::canonical(relocated / "shared"));
    CHECK(opened.role.directory ==
          std::filesystem::canonical(relocated / "client"));
    CHECK(opened.artifact_tree_path == std::filesystem::canonical(
              relocated / "client" /
              kPackedRoleArtifactTreeDirectory));
    const auto opened_server = open_packed_server_preprocessing(
        relocated / "shared", relocated / "server", storage,
        open_limits());
    CHECK(opened_server.root.semantic_identity == semantic);
    CHECK(opened_server.root.storage_identity == storage);
    CHECK(opened_server.role.artifact_tree.file_count == 2);
    CHECK(opened_server.artifact_tree_path == std::filesystem::canonical(
              relocated / "server" /
              kPackedRoleArtifactTreeDirectory));

    const std::string old_path = tree.tree.string();
    for (const auto &path :
         {relocated / "shared" / kPackedWorkloadStaticFilename,
          relocated / "shared" / kPackedManifestFilename,
          relocated / "server" / kPackedManifestFilename,
          relocated / "client" / kPackedManifestFilename}) {
        const auto encoded = read_file(path);
        const std::string contents(encoded.begin(), encoded.end());
        CHECK(contents.find(old_path) == std::string::npos);
    }
}

void check_semantic_identity_is_independent_of_storage_bytes() {
    TemporaryDirectory temporary;
    PublishedTree first = publish_tree(temporary.path(), "first");
    PublishedTree second = publish_tree(
        temporary.path(), "second", "different-server-serialization",
        "client-private-static-v1");
    CHECK(first.root.semantic_identity == second.root.semantic_identity);
    CHECK(first.root.storage_identity != second.root.storage_identity);
    CHECK(first.root.server.semantic_identity ==
          second.root.server.semantic_identity);
    CHECK(first.root.server.storage_identity !=
          second.root.server.storage_identity);

    PublishedTree third = publish_tree(
        temporary.path(), "third", "server-public-static-v1",
        "client-private-static-v1", "different-tensor-bytes");
    CHECK(first.root.server.semantic_identity ==
          third.root.server.semantic_identity);
    CHECK(first.root.server.storage_identity !=
          third.root.server.storage_identity);

    PublishedTree fourth = publish_tree(
        temporary.path(), "fourth", "server-public-static-v1",
        "client-private-static-v1", "canonical-packing-tensor",
        identity(19));
    CHECK(first.root.server.semantic_identity !=
          fourth.root.server.semantic_identity);
    CHECK(first.root.semantic_identity != fourth.root.semantic_identity);
}

void check_rejects_extra_files_swaps_and_truncation() {
    TemporaryDirectory temporary;
    PublishedTree extra = publish_tree(temporary.path(), "extra");
    write_file(extra.server / "unexpected.bin", "unowned");
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            extra.shared, extra.server, extra.root.storage_identity,
            open_limits());
    }));

    PublishedTree swapped = publish_tree(temporary.path(), "swapped");
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            swapped.shared, swapped.client,
            swapped.root.storage_identity, open_limits());
    }));
    std::filesystem::copy_file(
        swapped.client / kPackedRoleStaticFilename,
        swapped.server / kPackedRoleStaticFilename,
        std::filesystem::copy_options::overwrite_existing);
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            swapped.shared, swapped.server,
            swapped.root.storage_identity, open_limits());
    }));

    PublishedTree truncated = publish_tree(temporary.path(), "truncated");
    const auto root_path =
        truncated.shared / kPackedManifestFilename;
    auto root_bytes = read_file(root_path);
    root_bytes.resize(root_bytes.size() - 1U);
    std::ofstream output(root_path,
                         std::ios::binary | std::ios::out |
                             std::ios::trunc);
    output.write(reinterpret_cast<const char *>(root_bytes.data()),
                 static_cast<std::streamsize>(root_bytes.size()));
    output.close();
    CHECK(throws([&] {
        (void)open_packed_preprocessing_root(
            truncated.shared, truncated.root.storage_identity,
            open_limits());
    }));
}

void check_rejects_artifact_tree_tamper_and_layout_changes() {
    TemporaryDirectory temporary;
    PublishedTree tampered = publish_tree(temporary.path(), "tampered");
    const auto tampered_file =
        tampered.server / kPackedRoleArtifactTreeDirectory /
        "tensors" / "packing.bin";
    write_file(tampered_file, "canonical-packing-tensox");
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tampered.shared, tampered.server,
            tampered.root.storage_identity, open_limits());
    }));

    PublishedTree truncated = publish_tree(temporary.path(), "tree-truncated");
    write_file(truncated.server / kPackedRoleArtifactTreeDirectory /
                   "basefold" / "state-0" / "tree.bin",
               "short");
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            truncated.shared, truncated.server,
            truncated.root.storage_identity, open_limits());
    }));

    PublishedTree extra_file = publish_tree(temporary.path(), "tree-extra-file");
    write_file(extra_file.server / kPackedRoleArtifactTreeDirectory /
                   "unexpected.bin",
               "unowned");
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            extra_file.shared, extra_file.server,
            extra_file.root.storage_identity, open_limits());
    }));

    PublishedTree extra_directory =
        publish_tree(temporary.path(), "tree-extra-directory");
    std::filesystem::create_directory(
        extra_directory.server / kPackedRoleArtifactTreeDirectory /
        "unowned");
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            extra_directory.shared, extra_directory.server,
            extra_directory.root.storage_identity, open_limits());
    }));

    PublishedTree missing_directory =
        publish_tree(temporary.path(), "tree-missing-directory");
    std::filesystem::remove(
        missing_directory.server / kPackedRoleArtifactTreeDirectory /
        "empty");
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            missing_directory.shared, missing_directory.server,
            missing_directory.root.storage_identity, open_limits());
    }));
}

void check_enforces_artifact_tree_decode_limits() {
    TemporaryDirectory temporary;
    PublishedTree tree = publish_tree(temporary.path(), "bounded-tree");

    auto files = open_limits();
    files.max_artifact_tree_files = 1;
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity, files);
    }));

    auto directories = open_limits();
    directories.max_artifact_tree_directories = 3;
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity,
            directories);
    }));

    auto depth = open_limits();
    depth.max_artifact_tree_depth = 2;
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity, depth);
    }));

    auto path = open_limits();
    path.max_artifact_tree_relative_path_bytes =
        std::string_view("basefold/state-0/tree.bin").size() - 1U;
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity, path);
    }));

    auto per_file = open_limits();
    per_file.max_artifact_tree_file_bytes =
        std::string_view("canonical-packing-tensor").size() - 1U;
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity,
            per_file);
    }));

    auto aggregate = open_limits();
    aggregate.max_artifact_tree_bytes =
        tree.root.server.manifest_bytes;
    const auto opened = open_packed_server_preprocessing(
        tree.shared, tree.server, tree.root.storage_identity,
        open_limits());
    aggregate.max_artifact_tree_bytes =
        opened.role.artifact_tree.serialized_bytes - 1U;
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity,
            aggregate);
    }));

    CHECK(tree.root.manifest_bytes < tree.root.server.manifest_bytes);
    auto manifest = open_limits();
    manifest.max_manifest_bytes =
        tree.root.server.manifest_bytes - 1U;
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity,
            manifest);
    }));
}

void check_publication_is_manifest_last_and_transactional() {
    TemporaryDirectory temporary;
    const auto role = temporary.path() / "role";
    std::filesystem::create_directories(
        role / kPackedRoleArtifactTreeDirectory / "nested");
    write_file(role / kPackedRoleStaticFilename, "static");
    write_file(role / kPackedRoleArtifactTreeDirectory /
                   "nested" / "state.bin",
               "state");
    auto limits = publish_limits();
    limits.max_manifest_bytes = 64;
    CHECK(throws([&] {
        (void)publish_packed_role_manifest(
            role, PackedPreprocessingRole::Server, identity(1),
            identity(2), identity(3), limits);
    }));
    CHECK(!std::filesystem::exists(role / kPackedManifestFilename));
    CHECK(!std::filesystem::exists(
        role / (std::string(kPackedManifestFilename) + ".partial")));
    CHECK(read_file(role / kPackedRoleStaticFilename).size() == 6);
    CHECK(read_file(role / kPackedRoleArtifactTreeDirectory /
                    "nested" / "state.bin").size() == 5);

    const auto shared = temporary.path() / "shared";
    const auto server = temporary.path() / "server";
    const auto client = temporary.path() / "client";
    std::filesystem::create_directories(shared);
    std::filesystem::create_directories(
        server / kPackedRoleArtifactTreeDirectory);
    std::filesystem::create_directories(
        client / kPackedRoleArtifactTreeDirectory);
    const auto workload = test_workload();
    const auto normal = publish_limits();
    (void)publish_packed_workload_static_file(shared, workload, normal);
    write_file(server / kPackedRoleStaticFilename, "server");
    write_file(client / kPackedRoleStaticFilename, "client");
    (void)publish_packed_role_manifest(
        server, PackedPreprocessingRole::Server,
        workload.semantic_identity(), identity(4), identity(5), normal);
    (void)publish_packed_role_manifest(
        client, PackedPreprocessingRole::Client,
        workload.semantic_identity(), identity(6), identity(7), normal);
    auto impossible_space = normal;
    impossible_space.min_free_bytes =
        std::numeric_limits<std::uint64_t>::max();
    CHECK(throws([&] {
        (void)publish_packed_preprocessing_root(
            shared, server, client, workload, impossible_space);
    }));
    CHECK(!std::filesystem::exists(shared / kPackedManifestFilename));
    CHECK(!std::filesystem::exists(
        shared / (std::string(kPackedManifestFilename) + ".partial")));
}

void check_streams_large_artifact_tree_without_copying_files() {
    TemporaryDirectory temporary;
    const auto shared = temporary.path() / "shared";
    const auto server = temporary.path() / "server";
    const auto client = temporary.path() / "client";
    std::filesystem::create_directories(shared);
    std::filesystem::create_directories(
        server / kPackedRoleArtifactTreeDirectory / "basefold");
    std::filesystem::create_directories(
        client / kPackedRoleArtifactTreeDirectory);
    const auto workload = test_workload();
    auto limits = publish_limits();
    limits.max_manifest_bytes = 4096;
    const std::uint64_t large_bytes = 16ULL << 20U;
    limits.max_artifact_tree_file_bytes = large_bytes;
    limits.max_artifact_tree_bytes = large_bytes;
    (void)publish_packed_workload_static_file(shared, workload, limits);
    write_file(server / kPackedRoleStaticFilename, "server");
    write_file(client / kPackedRoleStaticFilename, "client");
    const auto large_path = server / kPackedRoleArtifactTreeDirectory /
                            "basefold" / "codeword.bin";
    write_repeated_file(large_path, large_bytes);
    const auto server_manifest = publish_packed_role_manifest(
        server, PackedPreprocessingRole::Server,
        workload.semantic_identity(), identity(10), identity(11), limits);
    (void)publish_packed_role_manifest(
        client, PackedPreprocessingRole::Client,
        workload.semantic_identity(), identity(12), identity(13), limits);
    const auto root = publish_packed_preprocessing_root(
        shared, server, client, workload, limits);
    CHECK(server_manifest.artifact_tree.serialized_bytes == large_bytes);
    CHECK(server_manifest.manifest_bytes < limits.max_manifest_bytes);
    CHECK(std::filesystem::file_size(large_path) == large_bytes);

    const PackedPreprocessingOpenLimits opening{
        .max_workload_bytes = limits.max_workload_bytes,
        .max_role_artifact_bytes = limits.max_role_artifact_bytes,
        .max_manifest_bytes = limits.max_manifest_bytes,
        .max_artifact_tree_files = limits.max_artifact_tree_files,
        .max_artifact_tree_directories =
            limits.max_artifact_tree_directories,
        .max_artifact_tree_depth = limits.max_artifact_tree_depth,
        .max_artifact_tree_relative_path_bytes =
            limits.max_artifact_tree_relative_path_bytes,
        .max_artifact_tree_file_bytes =
            limits.max_artifact_tree_file_bytes,
        .max_artifact_tree_bytes = limits.max_artifact_tree_bytes,
        .workload_decode = limits.workload_decode};
    const auto opened = open_packed_server_preprocessing(
        shared, server, root.storage_identity, opening);
    CHECK(opened.role.artifact_tree.serialized_bytes == large_bytes);
    CHECK(opened.role.artifact_tree.entries.size() == 2);

    std::uint64_t role_files = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(server)) {
        if (std::filesystem::is_regular_file(entry.symlink_status())) {
            ++role_files;
        }
    }
    CHECK(role_files == 3);
}

void check_rejects_overlapping_role_roots() {
    TemporaryDirectory temporary;
    const auto shared = temporary.path() / "publish-shared";
    const auto nested_server = shared / "nested-server";
    const auto client = temporary.path() / "publish-client";
    std::filesystem::create_directories(nested_server);
    std::filesystem::create_directories(client);
    const auto workload = test_workload();
    CHECK(throws([&] {
        (void)publish_packed_preprocessing_root(
            shared, nested_server, client, workload, publish_limits());
    }));

    PublishedTree tree = publish_tree(temporary.path(), "open-tree");
    const auto nested_role = tree.shared / "nested-role";
    std::filesystem::create_directory(nested_role);
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, nested_role, tree.root.storage_identity,
            open_limits());
    }));
}

#ifndef _WIN32
void check_rejects_symlinked_fixed_files() {
    TemporaryDirectory temporary;
    PublishedTree tree = publish_tree(temporary.path(), "symlink");
    const auto artifact = tree.server / kPackedRoleStaticFilename;
    const auto saved = temporary.path() / "saved-role-static.bin";
    std::filesystem::rename(artifact, saved);
    std::filesystem::create_symlink(saved, artifact);
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree.shared, tree.server, tree.root.storage_identity,
            open_limits());
    }));

    PublishedTree tree_root =
        publish_tree(temporary.path(), "symlink-tree-root");
    const auto artifact_tree =
        tree_root.server / kPackedRoleArtifactTreeDirectory;
    const auto saved_tree = temporary.path() / "saved-artifacts";
    std::filesystem::rename(artifact_tree, saved_tree);
    std::filesystem::create_directory_symlink(saved_tree, artifact_tree);
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            tree_root.shared, tree_root.server,
            tree_root.root.storage_identity, open_limits());
    }));

    PublishedTree leaf = publish_tree(temporary.path(), "symlink-tree-leaf");
    const auto leaf_path =
        leaf.server / kPackedRoleArtifactTreeDirectory /
        "tensors" / "packing.bin";
    const auto saved_leaf = temporary.path() / "saved-packing.bin";
    std::filesystem::rename(leaf_path, saved_leaf);
    std::filesystem::create_symlink(saved_leaf, leaf_path);
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            leaf.shared, leaf.server, leaf.root.storage_identity,
            open_limits());
    }));

    PublishedTree hardlinked =
        publish_tree(temporary.path(), "hardlinked-tree-leaf");
    const auto hardlinked_path =
        hardlinked.server / kPackedRoleArtifactTreeDirectory /
        "tensors" / "packing.bin";
    std::filesystem::create_hard_link(
        hardlinked_path, temporary.path() / "tree-leaf-alias.bin");
    CHECK(throws([&] {
        (void)open_packed_server_preprocessing(
            hardlinked.shared, hardlinked.server,
            hardlinked.root.storage_identity, open_limits());
    }));
}
#endif

void check_rejects_noncanonical_artifact_tree_names() {
    TemporaryDirectory temporary;
    const auto role = temporary.path() / "role";
    std::filesystem::create_directories(
        role / kPackedRoleArtifactTreeDirectory);
    write_file(role / kPackedRoleStaticFilename, "static");
    write_file(role / kPackedRoleArtifactTreeDirectory /
                   "not portable.bin",
               "value");
    CHECK(throws([&] {
        (void)publish_packed_role_manifest(
            role, PackedPreprocessingRole::Server, identity(1),
            identity(2), identity(3), publish_limits());
    }));
    CHECK(!std::filesystem::exists(role / kPackedManifestFilename));
}

} // namespace

int main() {
    laminate::test::Runner runner("Packed preprocessing storage");
    runner.run("round trips the consolidated Wide public index", check_shared_wide_index_codec);
    runner.run("restores canonical workload through shared circuit codec",
               check_workload_codec_and_shared_decoder);
    runner.run("derives exact quick-workload decoder requirements",
               check_exact_quick_workload_decode_requirements);
    runner.run("round trips with role-separated openers",
               check_round_trip_and_role_separation);
    runner.run("preserves semantic and storage identities after relocation",
               check_relocation_preserves_identities);
    runner.run("separates semantic identity from physical storage bytes",
               check_semantic_identity_is_independent_of_storage_bytes);
    runner.run("rejects extras, role swaps, byte swaps, and truncation",
               check_rejects_extra_files_swaps_and_truncation);
    runner.run("rejects artifact-tree tamper and exact-layout changes",
               check_rejects_artifact_tree_tamper_and_layout_changes);
    runner.run("enforces bounded artifact-tree manifest decoding",
               check_enforces_artifact_tree_decode_limits);
    runner.run("publishes manifests last with transactional cleanup",
               check_publication_is_manifest_last_and_transactional);
    runner.run("streams large trees without copying artifact files",
               check_streams_large_artifact_tree_without_copying_files);
    runner.run("rejects ancestor or descendant role roots",
               check_rejects_overlapping_role_roots);
#ifndef _WIN32
    runner.run("rejects symlinked fixed-name files",
               check_rejects_symlinked_fixed_files);
#endif
    runner.run("rejects noncanonical artifact-tree names",
               check_rejects_noncanonical_artifact_tree_names);
    return runner.summary();
}
