/// @file roles.cpp
/// @brief Persistent Folded/Laned role-state publication and restoration.

#include "laminate/protocol/packed/preprocessing/roles.hpp"

#include "laminate/packing/proof/matrix/oracle.hpp"

#include "../../codec/bounded_binary.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <fstream>
#include <limits>
#include <memory>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace laminate::protocol {
namespace {

using Bytes = codec::Bytes;
using codec::checked_u64;

constexpr std::array<std::uint8_t, 8> kRoleStaticMagic{
    'L', 'M', 'P', 'R', 'S', 'T', '0', '1'};
constexpr std::string_view kRoleStaticSemanticDomain =
    "LaminateImpl/PackedRoleStaticSemantic/v1";
constexpr std::string_view kRoleStaticChecksumDomain =
    "LaminateImpl/PackedRoleStaticChecksum/v1";
constexpr std::string_view kRoleTreeSemanticDomain =
    "LaminateImpl/PackedFixedRoleArtifactTree/v1";

std::span<const std::uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t *>(value.data()),
            value.size()};
}

Digest domain_hash(std::string_view domain,
                   std::span<const std::uint8_t> value) {
    Sha256Hasher hasher;
    hasher.update(bytes(domain));
    hasher.update(value);
    return hasher.finish();
}

template <typename Array> bool all_zero(const Array &value) {
    return std::ranges::all_of(
        value, [](std::uint8_t byte) { return byte == 0; });
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

class Writer final : public codec::Writer {
  public:
    void size(std::size_t value, const char *label) {
        codec::Writer::size(value, label);
    }
    void digest(const Digest &value) { raw(value); }
    void pcs_digest(const spartan::PcsDigest &value) { raw(value); }
    void string(std::string_view value, const char *label) {
        size(value.size(), label);
        raw(bytes(value));
    }
};

class Reader final : public codec::Reader {
  public:
    using codec::Reader::Reader;

    Digest digest(const char *label) {
        Digest result{};
        const auto encoded = take(result.size(), label);
        std::copy(encoded.begin(), encoded.end(), result.begin());
        return result;
    }
    spartan::PcsDigest pcs_digest(const char *label) {
        spartan::PcsDigest result{};
        const auto encoded = take(result.size(), label);
        std::copy(encoded.begin(), encoded.end(), result.begin());
        return result;
    }
    std::string string(std::size_t maximum, const char *label) {
        const std::size_t count = size(maximum, label);
        const auto encoded = take(count, label);
        return std::string(
            reinterpret_cast<const char *>(encoded.data()),
            encoded.size());
    }
    void finish() const {
        codec::Reader::finish(
            "packed role-static file has trailing data");
    }
};

bool supported_role(PackedPreprocessingRole role) {
    return role == PackedPreprocessingRole::Server ||
           role == PackedPreprocessingRole::Client;
}

bool supported_variant(PackingGkrVariant variant) {
    return variant == PackingGkrVariant::Folded ||
           variant == PackingGkrVariant::Laned;
}

payload::PayloadKind expected_payload_kind(PackingGkrVariant variant) {
    switch (variant) {
    case PackingGkrVariant::Folded:
        return payload::PayloadKind::Wide;
    case PackingGkrVariant::Laned:
        return payload::PayloadKind::Laned;
    }
    throw std::invalid_argument("packed role has an unknown variant");
}

std::vector<std::string> expected_artifact_paths(
    PackedPreprocessingRole role, std::size_t tensor_count) {
    if (role == PackedPreprocessingRole::Client) {
        return {};
    }
    std::vector<std::string> result{
        std::string(kPackedServerTensorColumnsRelativePath)};
    result.reserve(tensor_count + 1U);
    for (std::size_t tensor = 0; tensor < tensor_count; ++tensor) {
        result.push_back(
            packed_server_basefold_state_relative_path(tensor));
    }
    return result;
}

void validate_role_static(const PackedRoleStatic &state) {
    state.ciphertext_commitment_policy.validate();
    if (!supported_role(state.role) ||
        !supported_variant(state.variant) ||
        all_zero(state.workload_semantic_identity) ||
        all_zero(state.payload_digest) || all_zero(state.layered_digest) ||
        all_zero(state.circuit_digest) ||
        all_zero(state.public_setup_digest) ||
        state.ring_degree < 32U ||
        !std::has_single_bit(state.ring_degree) ||
        state.bhip_round_count == 0 || state.parameters.repetitions == 0 ||
        state.parameters.honest_error_bound == 0 ||
        state.basefold_parameters.log_rate == 0 ||
        state.basefold_parameters.query_count == 0 ||
        all_zero(state.spartan_setup_digest) ||
        state.factored_commitment.profile !=
            spartan::kFactoredMatrixProfileIdentifier ||
        all_zero(state.factored_commitment.circuit_digest) ||
        all_zero(state.factored_commitment.structure_digest) ||
        state.factored_commitment.tensors.empty() ||
        state.proof_ingress_rns_limbs_by_layer.empty() ||
        std::ranges::any_of(
            state.proof_ingress_rns_limbs_by_layer,
            [](std::size_t limbs) { return limbs == 0; }) ||
        all_zero(state.proof_ingress_schedule_digest) ||
        all_zero(state.fhe_context_storage_id) ||
        state.artifact_relative_paths != expected_artifact_paths(
            state.role, state.factored_commitment.tensors.size())) {
        throw std::invalid_argument(
            "packed role-static certificate is incomplete");
    }
    (void)conservative_packed_proof_ingress_policy_selection(
        state.variant, state.proof_ingress_policy);
    state.parameters.packing_radix.validate();
    for (const spartan::FactoredTensorCommitment &tensor :
         state.factored_commitment.tensors) {
        const spartan::PcsCommitment &columns = tensor.columns;
        if (tensor.shape.evaluation_count == 0 ||
            tensor.shape.column_count == 0 ||
            columns.scheme != spartan::BaseFoldPcs::kSchemeIdentifier ||
            all_zero(columns.root) ||
            columns.evaluation_count != tensor.shape.evaluation_count ||
            columns.width != tensor.shape.column_count ||
            columns.log_rate != state.basefold_parameters.log_rate ||
            columns.query_count != state.basefold_parameters.query_count) {
            throw std::invalid_argument(
                "packed role-static factored commitment is inconsistent");
        }
    }
}

void encode_factored_commitment(
    Writer &writer,
    const spartan::FactoredMatrixCommitment &commitment) {
    writer.u64(commitment.profile);
    writer.digest(commitment.circuit_digest);
    writer.digest(commitment.structure_digest);
    writer.u64(commitment.row_variables);
    writer.u64(commitment.column_variables);
    writer.size(commitment.tensors.size(), "factored tensor count");
    for (const spartan::FactoredTensorCommitment &tensor :
         commitment.tensors) {
        writer.u64(tensor.shape.evaluation_count);
        writer.u64(tensor.shape.column_count);
        writer.u64(tensor.columns.scheme);
        writer.pcs_digest(tensor.columns.root);
        writer.u64(tensor.columns.evaluation_count);
        writer.u64(tensor.columns.width);
        writer.u64(tensor.columns.log_rate);
        writer.u64(tensor.columns.query_count);
    }
}

spartan::FactoredMatrixCommitment decode_factored_commitment(
    Reader &reader, const PackedRoleStaticDecodeLimits &limits) {
    spartan::FactoredMatrixCommitment result;
    result.profile = reader.u64("factored profile");
    result.circuit_digest = reader.digest("factored circuit digest");
    result.structure_digest =
        reader.digest("factored structure digest");
    result.row_variables = reader.u64("factored row variables");
    result.column_variables = reader.u64("factored column variables");
    const std::size_t tensor_count = reader.size(
        limits.max_factored_tensors, "factored tensor count");
    result.tensors.reserve(tensor_count);
    for (std::size_t tensor = 0; tensor < tensor_count; ++tensor) {
        spartan::FactoredTensorCommitment selected;
        selected.shape.evaluation_count =
            reader.u64("tensor evaluation count");
        selected.shape.column_count = reader.u64("tensor column count");
        selected.columns.scheme = reader.u64("tensor PCS scheme");
        selected.columns.root = reader.pcs_digest("tensor PCS root");
        selected.columns.evaluation_count =
            reader.u64("tensor PCS evaluation count");
        selected.columns.width = reader.u64("tensor PCS width");
        const std::uint64_t log_rate = reader.u64("tensor PCS log rate");
        const std::uint64_t query_count =
            reader.u64("tensor PCS query count");
        if (log_rate > std::numeric_limits<std::uint32_t>::max() ||
            query_count > std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument(
                "packed role-static PCS parameters exceed u32");
        }
        selected.columns.log_rate =
            static_cast<std::uint32_t>(log_rate);
        selected.columns.query_count =
            static_cast<std::uint32_t>(query_count);
        result.tensors.push_back(std::move(selected));
    }
    return result;
}

Bytes encode_role_static_body(const PackedRoleStatic &state) {
    validate_role_static(state);
    Writer writer;
    writer.raw(kRoleStaticMagic);
    writer.u64(kPackedRoleStaticVersion);
    writer.u64(0);
    writer.u64(static_cast<std::uint64_t>(state.role));
    writer.u64(static_cast<std::uint64_t>(state.variant));
    writer.u64(state.ciphertext_commitment_policy.wire_code());
    writer.digest(state.workload_semantic_identity);
    writer.digest(state.payload_digest);
    writer.digest(state.layered_digest);
    writer.digest(state.circuit_digest);
    writer.digest(state.public_setup_digest);
    writer.size(state.ring_degree, "ring degree");
    writer.size(state.bhip_round_count, "BhIP round count");
    writer.size(state.parameters.repetitions, "test repetitions");
    writer.u64(state.parameters.honest_error_bound);
    writer.u64(state.parameters.packing_radix.plaintext_modulus);
    writer.u64(state.parameters.packing_radix.base);
    writer.size(state.parameters.packing_radix.digit_count,
                "packing digit count");
    writer.size(state.basefold_parameters.log_rate, "BaseFold log rate");
    writer.size(state.basefold_parameters.query_count,
                "BaseFold query count");
    writer.digest(state.spartan_setup_digest);
    encode_factored_commitment(writer, state.factored_commitment);
    writer.string(state.proof_ingress_policy, "ingress policy");
    writer.size(state.proof_ingress_rns_limbs_by_layer.size(),
                "ingress layer count");
    for (const std::size_t limbs :
         state.proof_ingress_rns_limbs_by_layer) {
        writer.size(limbs, "ingress RNS limbs");
    }
    writer.digest(state.proof_ingress_schedule_digest);
    writer.digest(state.fhe_context_storage_id);
    writer.size(state.artifact_relative_paths.size(),
                "artifact relative-path count");
    for (const std::string &path : state.artifact_relative_paths) {
        writer.string(path, "artifact relative path");
    }
    return std::move(writer).finish();
}

Digest role_static_semantic_identity(const PackedRoleStatic &state) {
    const Bytes body = encode_role_static_body(state);
    return domain_hash(kRoleStaticSemanticDomain, body);
}

Digest role_tree_semantic_identity(const PackedRoleStatic &state) {
    Writer writer;
    writer.digest(state.semantic_identity);
    writer.u64(static_cast<std::uint64_t>(state.role));
    writer.size(state.artifact_relative_paths.size(),
                "artifact relative-path count");
    if (state.role == PackedPreprocessingRole::Server) {
        writer.string(state.artifact_relative_paths.front(),
                      "tensor artifact path");
        writer.digest(spartan::factored_matrix_artifact_identity(
            state.factored_commitment));
        for (std::size_t tensor = 0;
             tensor < state.factored_commitment.tensors.size(); ++tensor) {
            writer.string(state.artifact_relative_paths[tensor + 1U],
                          "BaseFold state path");
            writer.digest(spartan::basefold_external_state_identity(
                state.factored_commitment.tensors[tensor].columns));
        }
    }
    return domain_hash(kRoleTreeSemanticDomain, writer.view());
}

PackedRoleStatic decode_role_static(
    std::span<const std::uint8_t> encoded,
    const PackedRoleStaticDecodeLimits &limits) {
    Reader reader(encoded);
    const auto magic =
        reader.take(kRoleStaticMagic.size(), "role-static magic");
    if (!std::equal(kRoleStaticMagic.begin(), kRoleStaticMagic.end(),
                    magic.begin()) ||
        reader.u64("role-static version") != kPackedRoleStaticVersion ||
        reader.u64("role-static flags") != 0U) {
        throw std::invalid_argument("unsupported packed role-static file");
    }
    const std::uint64_t role_word = reader.u64("packed role");
    const std::uint64_t variant_word = reader.u64("packed variant");
    if (role_word > static_cast<std::uint64_t>(
                        PackedPreprocessingRole::Client) ||
        role_word == 0 ||
        variant_word >
            static_cast<std::uint64_t>(PackingGkrVariant::Laned)) {
        throw std::invalid_argument(
            "packed role-static has an unknown role or variant");
    }
    PackedRoleStatic result;
    result.role = static_cast<PackedPreprocessingRole>(role_word);
    result.variant = static_cast<PackingGkrVariant>(variant_word);
    result.ciphertext_commitment_policy =
        gkr::CiphertextCommitmentPolicy::from_wire_code(
            reader.u64("ciphertext commitment policy"));
    result.workload_semantic_identity =
        reader.digest("workload semantic identity");
    result.payload_digest = reader.digest("payload digest");
    result.layered_digest = reader.digest("layered digest");
    result.circuit_digest = reader.digest("circuit digest");
    result.public_setup_digest = reader.digest("public setup digest");
    result.ring_degree = reader.size(
        std::numeric_limits<std::size_t>::max(), "ring degree");
    result.bhip_round_count = reader.size(
        std::numeric_limits<std::size_t>::max(), "BhIP round count");
    result.parameters.repetitions = reader.size(
        std::numeric_limits<std::size_t>::max(), "test repetitions");
    result.parameters.honest_error_bound =
        reader.u64("honest error bound");
    result.parameters.packing_radix.plaintext_modulus =
        reader.u64("packing plaintext modulus");
    result.parameters.packing_radix.base = reader.u64("packing radix");
    result.parameters.packing_radix.digit_count = reader.size(
        std::numeric_limits<std::size_t>::max(), "packing digit count");
    result.basefold_parameters.log_rate = reader.size(
        std::numeric_limits<std::size_t>::digits - 1U,
        "BaseFold log rate");
    result.basefold_parameters.query_count = reader.size(
        std::numeric_limits<std::uint32_t>::max(),
        "BaseFold query count");
    result.spartan_setup_digest = reader.digest("Spartan setup digest");
    result.factored_commitment =
        decode_factored_commitment(reader, limits);
    result.proof_ingress_policy = reader.string(
        128, "proof-ingress policy");
    const std::size_t ingress_count = reader.size(
        limits.max_ingress_layers, "proof-ingress layer count");
    result.proof_ingress_rns_limbs_by_layer.reserve(ingress_count);
    for (std::size_t layer = 0; layer < ingress_count; ++layer) {
        result.proof_ingress_rns_limbs_by_layer.push_back(reader.size(
            std::numeric_limits<std::size_t>::max(),
            "proof-ingress RNS limbs"));
    }
    result.proof_ingress_schedule_digest =
        reader.digest("proof-ingress schedule digest");
    result.fhe_context_storage_id =
        reader.digest("FHE context storage identity");
    const std::size_t path_count = reader.size(
        limits.max_factored_tensors + 1U,
        "artifact relative-path count");
    result.artifact_relative_paths.reserve(path_count);
    for (std::size_t path = 0; path < path_count; ++path) {
        result.artifact_relative_paths.push_back(reader.string(
            limits.max_relative_path_bytes,
            "artifact relative path"));
    }
    const std::size_t semantic_offset = reader.position();
    result.semantic_identity = reader.digest("role-static semantic identity");
    const Digest checksum = reader.digest("role-static checksum");
    reader.finish();
    validate_role_static(result);
    if (result.semantic_identity !=
            role_static_semantic_identity(result) ||
        checksum != domain_hash(kRoleStaticChecksumDomain,
                                encoded.first(semantic_offset +
                                              sizeof(Digest))) ||
        encode_packed_role_static(result) !=
            Bytes(encoded.begin(), encoded.end())) {
        throw std::invalid_argument(
            "packed role-static file is noncanonical or corrupted");
    }
    return result;
}

std::filesystem::path normalize_empty_private_directory(
    const std::filesystem::path &requested, const char *label) {
    if (requested.empty()) {
        throw std::invalid_argument(std::string(label) + " path is empty");
    }
    const auto status = std::filesystem::symlink_status(requested);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_empty(requested)) {
        throw std::invalid_argument(
            std::string(label) + " must be an empty real directory");
    }
#ifndef _WIN32
    struct stat native {};
    if (::stat(requested.c_str(), &native) != 0) {
        throw std::filesystem::filesystem_error(
            "failed to inspect packed role directory", requested,
            std::error_code(errno, std::generic_category()));
    }
    if (native.st_uid != ::geteuid() ||
        (native.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw std::invalid_argument(
            std::string(label) + " must be owner-private");
    }
#endif
    return std::filesystem::canonical(requested);
}

bool path_prefix(const std::filesystem::path &prefix,
                 const std::filesystem::path &path) {
    auto left = prefix.begin();
    auto right = path.begin();
    while (left != prefix.end() && right != path.end() &&
           *left == *right) {
        ++left;
        ++right;
    }
    return left == prefix.end();
}

void require_disjoint(
    std::span<const std::filesystem::path> paths) {
    for (std::size_t left = 0; left < paths.size(); ++left) {
        for (std::size_t right = left + 1U; right < paths.size(); ++right) {
            if (path_prefix(paths[left], paths[right]) ||
                path_prefix(paths[right], paths[left])) {
                throw std::invalid_argument(
                    "packed role publication roots must be disjoint");
            }
        }
    }
}

void make_private_directory(const std::filesystem::path &path) {
    if (!std::filesystem::create_directory(path)) {
        throw std::runtime_error(
            "failed to create packed role setup directory");
    }
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
}

void write_role_static_file(const std::filesystem::path &role_directory,
                            const PackedRoleStatic &state,
                            const PackedRoleStaticDecodeLimits &limits) {
    const Bytes encoded = encode_packed_role_static(state);
    if (limits.max_encoded_bytes == 0 ||
        encoded.size() > limits.max_encoded_bytes) {
        throw std::invalid_argument(
            "packed role-static file exceeds its publication limit");
    }
    const std::filesystem::path path =
        role_directory / std::string(kPackedRoleStaticFilename);
    if (std::filesystem::exists(std::filesystem::symlink_status(path))) {
        throw std::invalid_argument(
            "packed role-static publication target exists");
    }
    std::ofstream output(path, std::ios::binary | std::ios::out);
    if (!output ||
        (encoded.size() != 0 &&
         !output.write(reinterpret_cast<const char *>(encoded.data()),
                       static_cast<std::streamsize>(encoded.size())))) {
        throw std::runtime_error("failed to write packed role-static file");
    }
    output.close();
    if (!output) {
        throw std::runtime_error("failed to close packed role-static file");
    }
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_read |
                  std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
}

Bytes read_role_static_file(
    const std::filesystem::path &path,
    const PackedRoleStaticDecodeLimits &limits) {
    const auto status = std::filesystem::symlink_status(path);
    if (!std::filesystem::is_regular_file(status) ||
        std::filesystem::is_symlink(status) ||
        limits.max_encoded_bytes == 0) {
        throw std::invalid_argument(
            "packed role-static path is not a regular bounded file");
    }
    const std::uintmax_t size = std::filesystem::file_size(path);
    if (size > limits.max_encoded_bytes ||
        size > std::numeric_limits<std::size_t>::max() ||
        size > static_cast<std::uintmax_t>(
                   std::numeric_limits<std::streamoff>::max())) {
        throw std::invalid_argument(
            "packed role-static file exceeds its byte limit");
    }
    Bytes result(static_cast<std::size_t>(size));
    std::ifstream input(path, std::ios::binary);
    if (!input ||
        (size != 0 &&
         !input.read(reinterpret_cast<char *>(result.data()),
                     static_cast<std::streamsize>(size))) ||
        input.peek() != std::ifstream::traits_type::eof()) {
        throw std::runtime_error("failed to read packed role-static file");
    }
    return result;
}

struct PublicationRootIdentity {
    std::filesystem::path path;
#ifndef _WIN32
    std::uintmax_t device = 0;
    std::uintmax_t inode = 0;
#endif
};

PublicationRootIdentity capture_publication_root(
    const std::filesystem::path &path) {
    PublicationRootIdentity result{.path = path};
#ifndef _WIN32
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0 ||
        !S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
        throw std::invalid_argument(
            "packed role publication root is not a real directory");
    }
    result.device = static_cast<std::uintmax_t>(status.st_dev);
    result.inode = static_cast<std::uintmax_t>(status.st_ino);
#endif
    return result;
}

bool same_publication_root(const PublicationRootIdentity &expected) {
#ifdef _WIN32
    const auto status = std::filesystem::symlink_status(expected.path);
    return std::filesystem::is_directory(status) &&
           !std::filesystem::is_symlink(status);
#else
    struct stat status {};
    return ::lstat(expected.path.c_str(), &status) == 0 &&
           S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode) &&
           static_cast<std::uintmax_t>(status.st_dev) == expected.device &&
           static_cast<std::uintmax_t>(status.st_ino) == expected.inode;
#endif
}

class PublicationTransaction {
  public:
    explicit PublicationTransaction(
        std::vector<std::filesystem::path> roots) {
        roots_.reserve(roots.size());
        for (const std::filesystem::path &root : roots) {
            roots_.push_back(capture_publication_root(root));
        }
    }
    ~PublicationTransaction() {
        if (!armed_) {
            return;
        }
        for (const auto &root : roots_) {
            if (!same_publication_root(root)) {
                continue;
            }
            std::error_code iteration_error;
            for (auto entry = std::filesystem::directory_iterator(
                     root.path, iteration_error);
                 !iteration_error &&
                 entry != std::filesystem::directory_iterator();) {
                const auto child = entry->path();
                entry.increment(iteration_error);
                std::error_code removal_error;
                std::filesystem::remove_all(child, removal_error);
            }
        }
    }
    void commit() { armed_ = false; }

  private:
    std::vector<PublicationRootIdentity> roots_;
    bool armed_ = true;
};

std::size_t expected_bhip_round_count(
    PackingGkrVariant variant,
    const payload::LayeredCircuit &circuit) {
    return variant == PackingGkrVariant::Folded
               ? folded_bhip_round_count(circuit)
               : laned_bhip_round_count(circuit);
}

PackedRoleStatic make_role_static(
    PackedPreprocessingRole role,
    const CertifiedPackedWorkloadStatic &workload,
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    const ConservativePackedProofIngressSchedule &schedule,
    const spartan::FactoredMatrixCommitment &commitment,
    const Digest &spartan_setup_digest,
    const Digest &fhe_context_storage_id) {
    PackedRoleStatic result{
        .role = role,
        .variant = specification.variant,
        .ciphertext_commitment_policy =
            specification.ciphertext_commitment_policy,
        .workload_semantic_identity = workload.semantic_identity(),
        .payload_digest = workload.payload_digest(),
        .layered_digest = workload.layered_digest(),
        .circuit_digest = workload.circuit_digest(),
        .public_setup_digest = workload.setup_digest(),
        .ring_degree = specification.ring_degree,
        .bhip_round_count = specification.bhip_round_count,
        .parameters = specification.parameters,
        .basefold_parameters = specification.basefold_parameters,
        .spartan_setup_digest = spartan_setup_digest,
        .factored_commitment = commitment,
        .proof_ingress_policy = std::string(schedule.policy()),
        .proof_ingress_rns_limbs_by_layer =
            std::vector<std::size_t>(
                schedule.rns_limbs_by_layer().begin(),
                schedule.rns_limbs_by_layer().end()),
        .proof_ingress_schedule_digest = schedule.digest(),
        .fhe_context_storage_id = fhe_context_storage_id,
        .artifact_relative_paths = expected_artifact_paths(
            role, commitment.tensors.size()),
    };
    result.semantic_identity = role_static_semantic_identity(result);
    validate_role_static(result);
    return result;
}

struct RestoredCommon {
    packing::ProofOfPackingStructuredMetadata relation;
    std::shared_ptr<const spartan::FactoredMatrixStructure> structure;
    std::shared_ptr<const spartan::BaseFoldPcs> pcs;
    ConservativePackedProofIngressSchedule ingress;
    spartan::VerifierKey verifier_key;
};

void validate_fixed_tree_layout(
    const OpenedPackedRolePreprocessing &opened,
    const PackedRoleStatic &state) {
    if (state.role == PackedPreprocessingRole::Client) {
        if (!opened.role.artifact_tree.entries.empty() ||
            opened.role.artifact_tree.file_count != 0 ||
            opened.role.artifact_tree.directory_count != 0 ||
            opened.role.artifact_tree.serialized_bytes != 0) {
            throw std::invalid_argument(
                "packed client artifact tree must be empty");
        }
        return;
    }
    const std::set<std::string> allowed(
        state.artifact_relative_paths.begin(),
        state.artifact_relative_paths.end());
    std::set<std::string> roots;
    for (const PackedStoredArtifactTreeEntry &entry :
         opened.role.artifact_tree.entries) {
        const std::size_t slash = entry.relative_path.find('/');
        const std::string root = entry.relative_path.substr(0, slash);
        if (!allowed.contains(root)) {
            throw std::invalid_argument(
                "packed server artifact tree has an unexpected root");
        }
        if (slash == std::string::npos &&
            entry.kind == PackedArtifactTreeEntryKind::Directory) {
            roots.insert(root);
        }
    }
    if (roots != allowed) {
        throw std::invalid_argument(
            "packed server artifact tree omits a fixed root");
    }
}

RestoredCommon restore_common(
    const OpenedPackedRolePreprocessing &opened,
    const PackedRoleStatic &state,
    const Digest &expected_fhe_context_storage_id) {
    const CertifiedPackedWorkloadStatic &workload = opened.workload;
    if (state.role != opened.role.role ||
        state.semantic_identity != opened.role.role_artifact.semantic_identity ||
        role_tree_semantic_identity(state) !=
            opened.role.artifact_tree.semantic_identity ||
        state.workload_semantic_identity != workload.semantic_identity() ||
        state.payload_digest != workload.payload_digest() ||
        state.layered_digest != workload.layered_digest() ||
        state.circuit_digest != workload.circuit_digest() ||
        state.public_setup_digest != workload.setup_digest() ||
        state.fhe_context_storage_id != expected_fhe_context_storage_id ||
        workload.circuit().shape.kind != expected_payload_kind(state.variant) ||
        workload.circuit().shape.slot_count != state.ring_degree ||
        expected_bhip_round_count(state.variant, workload.circuit()) !=
            state.bhip_round_count) {
        throw std::invalid_argument(
            "packed role-static semantics do not match the workload or FHE context");
    }
    validate_fixed_tree_layout(opened, state);

    ConservativePackedProofIngressSchedule ingress =
        derive_conservative_packed_proof_ingress_schedule(
            state.variant, workload.payload(), workload.circuit(),
            workload.public_setup(),
            conservative_packed_proof_ingress_policy_selection(
                state.variant, state.proof_ingress_policy));
    if (state.proof_ingress_policy != ingress.policy() ||
        state.proof_ingress_schedule_digest != ingress.digest() ||
        !std::ranges::equal(
            state.proof_ingress_rns_limbs_by_layer,
            ingress.rns_limbs_by_layer())) {
        throw std::invalid_argument(
            "packed role-static proof-ingress schedule is not the fixed policy");
    }

    const packing::PackingLayout alignment =
        packing::make_fixed_message_coset_packing_layout(
            state.ring_degree, state.bhip_round_count,
            state.ring_degree / fhe::kFixedMessageCellCount);
    packing::ProofOfPackingStructuredMetadata relation =
        packing::make_proof_of_packing_structured_metadata(
            alignment, state.parameters,
            state.ciphertext_commitment_policy);
    relation.validate();
    auto structure = packing::make_proof_of_packing_factored_structure(
        relation.relation_plan, relation.r1cs_layout,
        relation.tensor_mappings, relation.circuit_metadata);
    auto pcs = std::make_shared<const spartan::BaseFoldPcs>(
        state.basefold_parameters);
    auto factored_verifier =
        std::make_shared<const spartan::FactoredMatrixVerifierKey>(
            spartan::FactoredMatrixVerifierKey{
                .commitment = state.factored_commitment,
                .structure = structure,
            });
    spartan::VerifierKey verifier{
        .circuit_metadata = relation.circuit_metadata,
        .setup_digest = state.spartan_setup_digest,
        .pcs_scheme = pcs->scheme_identifier(),
        .options = {.matrix_evaluation =
                        spartan::MatrixEvaluationMode::CommittedFactored},
        .direct_matrix = nullptr,
        .matrix_oracle = nullptr,
        .factored_computation = std::move(factored_verifier),
    };
    spartan::validate_verifier_key(verifier, *pcs);
    return RestoredCommon{
        .relation = std::move(relation),
        .structure = std::move(structure),
        .pcs = std::move(pcs),
        .ingress = std::move(ingress),
        .verifier_key = std::move(verifier),
    };
}

PackedRoleStatic open_role_static(
    const OpenedPackedRolePreprocessing &opened,
    PackedPreprocessingRole role,
    const PackedRoleStaticDecodeLimits &limits) {
    const Bytes encoded = read_role_static_file(
        opened.role_artifact_path, limits);
    if (sha256(encoded) != opened.role.role_artifact.file_digest) {
        throw std::invalid_argument(
            "packed role-static file differs from its role manifest");
    }
    return decode_authenticated_packed_role_static(
        encoded, role, opened.role.role_artifact.file_digest,
        opened.role.role_artifact.semantic_identity, limits);
}

TranscriptPackingSpartanVerifierSetup make_verifier_setup(
    const PackedRoleStatic &state, RestoredCommon &common) {
    return TranscriptPackingSpartanVerifierSetup{
        .variant = state.variant,
        .bhip_round_count = state.bhip_round_count,
        .alignment_layout = common.relation.alignment_layout,
        .relation_plan = common.relation.relation_plan,
        .parameters = common.relation.parameters,
        .radix = common.relation.parameters.packing_radix,
        .basefold_parameters = state.basefold_parameters,
        .spartan = common.verifier_key,
    };
}

PackedPreprocessingOpenLimits storage_open_limits(
    const PackedPreprocessingPublishLimits &limits) {
    return PackedPreprocessingOpenLimits{
        .max_workload_bytes = limits.max_workload_bytes,
        .max_role_artifact_bytes = limits.max_role_artifact_bytes,
        .max_manifest_bytes = limits.max_manifest_bytes,
        .max_artifact_tree_files = limits.max_artifact_tree_files,
        .max_artifact_tree_directories =
            limits.max_artifact_tree_directories,
        .max_artifact_tree_depth = limits.max_artifact_tree_depth,
        .max_artifact_tree_relative_path_bytes =
            limits.max_artifact_tree_relative_path_bytes,
        .max_artifact_tree_file_bytes = limits.max_artifact_tree_file_bytes,
        .max_artifact_tree_bytes = limits.max_artifact_tree_bytes,
        .workload_decode = limits.workload_decode,
    };
}

bool covers_workload_decode_requirements(
    const PackedWorkloadStaticDecodeLimits &limits,
    const PackedWorkloadStaticDecodeLimits &requirements) {
    return limits.max_artifact_bytes >= requirements.max_artifact_bytes &&
           limits.max_slots >= requirements.max_slots &&
           limits.max_payload_plaintexts >=
               requirements.max_payload_plaintexts &&
           limits.max_payload_gates >= requirements.max_payload_gates &&
           limits.max_payload_outputs >= requirements.max_payload_outputs &&
           limits.max_layers >= requirements.max_layers &&
           limits.max_layer_gates >= requirements.max_layer_gates &&
           limits.max_affine_terms >= requirements.max_affine_terms &&
           limits.max_storage_entries >=
               requirements.max_storage_entries &&
           limits.max_gate_tables >= requirements.max_gate_tables;
}

} // namespace

std::string packed_server_basefold_state_relative_path(
    std::size_t tensor_index) {
    return "basefold-state-" + std::to_string(tensor_index);
}

std::vector<std::uint8_t> encode_packed_role_static(
    const PackedRoleStatic &state) {
    const Bytes body = encode_role_static_body(state);
    const Digest semantic = domain_hash(kRoleStaticSemanticDomain, body);
    if (state.semantic_identity != semantic) {
        throw std::invalid_argument(
            "packed role-static semantic identity is inconsistent");
    }
    Writer writer;
    writer.raw(body);
    writer.digest(semantic);
    writer.digest(domain_hash(kRoleStaticChecksumDomain, writer.view()));
    return std::move(writer).finish();
}

PackedRoleStatic decode_authenticated_packed_role_static(
    std::span<const std::uint8_t> encoded,
    PackedPreprocessingRole expected_role,
    const Digest &expected_file_digest,
    const Digest &expected_semantic_identity,
    const PackedRoleStaticDecodeLimits &limits) {
    if (!supported_role(expected_role) || limits.max_encoded_bytes == 0 ||
        limits.max_ingress_layers == 0 ||
        limits.max_factored_tensors == 0 ||
        limits.max_relative_path_bytes == 0 || encoded.empty() ||
        encoded.size() > limits.max_encoded_bytes ||
        all_zero(expected_file_digest) ||
        all_zero(expected_semantic_identity) ||
        sha256(encoded) != expected_file_digest) {
        throw std::invalid_argument(
            "packed role-static authentication or limits are invalid");
    }
    PackedRoleStatic result = decode_role_static(encoded, limits);
    if (result.role != expected_role ||
        result.semantic_identity != expected_semantic_identity) {
        throw std::invalid_argument(
            "packed role-static has the wrong authenticated role or semantics");
    }
    return result;
}

PackedRolePreprocessingOpenLimits packed_role_preprocessing_open_limits(
    const PackedRolePreprocessingPublishLimits &limits) {
    return PackedRolePreprocessingOpenLimits{
        .storage = storage_open_limits(limits.storage),
        .role_static = limits.role_static,
    };
}

PackedRolePreprocessingPublicationPlan
plan_packed_role_preprocessing_publication(
    const CertifiedPackedWorkloadStatic &workload,
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    const Digest &fhe_context_storage_id) {
    if (all_zero(fhe_context_storage_id) ||
        specification.ring_degree != workload.circuit().shape.slot_count ||
        specification.variant !=
            (workload.circuit().shape.kind == payload::PayloadKind::Wide
                 ? PackingGkrVariant::Folded
                 : PackingGkrVariant::Laned) ||
        specification.bhip_round_count != expected_bhip_round_count(
            specification.variant, workload.circuit())) {
        throw std::invalid_argument(
            "packed role sizing geometry does not match the workload");
    }
    PackedRolePreprocessingPublicationPlan result{
        .transcript_packing =
            plan_transcript_packing_external_preprocessing(specification),
    };
    const std::size_t workload_bytes =
        encode_packed_workload_static(workload).size();
    result.workload_decode_requirements =
        packed_workload_static_decode_requirements(
            workload, workload_bytes);
    const auto structure =
        packing::make_proof_of_packing_factored_structure(
            result.transcript_packing.relation.relation_plan,
            result.transcript_packing.relation.r1cs_layout,
            result.transcript_packing.relation.tensor_mappings,
            result.transcript_packing.relation.circuit_metadata);
    if (structure->tensor_count() !=
        result.transcript_packing.factored.tensors.size()) {
        throw std::logic_error(
            "packed role sizing structure and artifact plan disagree");
    }

    spartan::FactoredMatrixCommitment placeholder{
        .profile = spartan::kFactoredMatrixProfileIdentifier,
        .circuit_digest = structure->circuit_digest(),
        .structure_digest = structure->structure_digest(),
        .row_variables = structure->row_variables(),
        .column_variables = structure->column_variables(),
    };
    placeholder.tensors.reserve(structure->tensor_count());
    for (std::size_t tensor = 0; tensor < structure->tensor_count();
         ++tensor) {
        spartan::PcsDigest root{};
        root.fill(static_cast<std::uint8_t>(tensor % 251U + 1U));
        const auto &planned = result.transcript_packing.factored.tensors[tensor];
        placeholder.tensors.push_back({
            .shape = planned.shape,
            .columns = {
                .scheme = spartan::BaseFoldPcs::kSchemeIdentifier,
                .root = root,
                .evaluation_count = planned.shape.evaluation_count,
                .width = planned.shape.column_count,
                .log_rate = static_cast<std::uint32_t>(
                    specification.basefold_parameters.log_rate),
                .query_count = static_cast<std::uint32_t>(
                    specification.basefold_parameters.query_count),
            },
        });
    }
    Digest placeholder_setup{};
    placeholder_setup.fill(1U);
    const ConservativePackedProofIngressSchedule schedule =
        derive_conservative_packed_proof_ingress_schedule(
            specification.variant, workload.payload(), workload.circuit(),
            workload.public_setup(), specification.proof_ingress_policy);
    const PackedRoleStatic server = make_role_static(
        PackedPreprocessingRole::Server, workload, specification, schedule,
        placeholder, placeholder_setup, fhe_context_storage_id);
    const PackedRoleStatic client = make_role_static(
        PackedPreprocessingRole::Client, workload, specification, schedule,
        placeholder, placeholder_setup, fhe_context_storage_id);
    result.server_role_static_bytes = checked_u64(
        encode_packed_role_static(server).size(),
        "server role-static bytes");
    result.client_role_static_bytes = checked_u64(
        encode_packed_role_static(client).size(),
        "client role-static bytes");

    result.server_artifacts.directory_count = checked_add(
        1U,
        checked_u64(result.transcript_packing.factored.tensors.size(),
                    "server artifact directory count"),
        "server artifact directory count");
    // One canonical array per tensor column plus its manifest. Each external
    // BaseFold state contains message and codeword arrays for every column,
    // one Merkle-tree array, and one manifest.
    result.server_artifacts.file_count = 1U;
    for (const auto &tensor : result.transcript_packing.factored.tensors) {
        const std::uint64_t width = tensor.shape.column_count;
        result.server_artifacts.file_count = checked_add(
            result.server_artifacts.file_count, width,
            "canonical tensor artifact file count");
        result.server_artifacts.file_count = checked_add(
            result.server_artifacts.file_count,
            checked_add(checked_multiply(2U, width,
                                         "BaseFold state file count"),
                        2U, "BaseFold state file count"),
            "server artifact file count");
    }
    result.server_artifacts.serialized_bytes =
        result.transcript_packing.factored.persistent_output_physical_bytes;
    return result;
}

namespace detail {

OpenedPackedServerRoleCore open_packed_server_role_core(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &server_directory,
    const Digest &expected_root_storage_identity,
    const Digest &expected_fhe_context_storage_id,
    const PackedRolePreprocessingOpenLimits &limits) {
    OpenedPackedRolePreprocessing opened =
        open_packed_server_preprocessing(
            shared_directory, server_directory,
            expected_root_storage_identity, limits.storage);
    PackedRoleStatic state = open_role_static(
        opened, PackedPreprocessingRole::Server, limits.role_static);
    RestoredCommon common = restore_common(
        opened, state, expected_fhe_context_storage_id);

    const std::filesystem::path tensor_path =
        opened.artifact_tree_path /
        state.artifact_relative_paths.front();
    auto tensor_artifact = spartan::open_factored_matrix_artifact(
        tensor_path, state.factored_commitment);
    std::vector<spartan::FactoredTensorProverKey> tensors;
    tensors.reserve(state.factored_commitment.tensors.size());
    for (std::size_t tensor = 0;
         tensor < state.factored_commitment.tensors.size(); ++tensor) {
        tensors.push_back(spartan::FactoredTensorProverKey{
            .columns = {},
            .opening_state = common.pcs->open_external_prover_state(
                opened.artifact_tree_path /
                    state.artifact_relative_paths[tensor + 1U],
                state.factored_commitment.tensors[tensor].columns),
            .opening_state_source =
                spartan::FactoredTensorProverKey::OpeningStateSource::External,
        });
    }
    auto factored_prover =
        std::make_shared<const spartan::FactoredMatrixProverKey>(
            spartan::FactoredMatrixProverKey{
                .commitment = state.factored_commitment,
                .structure = common.structure,
                .tensors = std::move(tensors),
                .tensor_column_source =
                    spartan::FactoredTensorColumnSource::Artifact,
                .tensor_columns_artifact = std::move(tensor_artifact),
            });
    spartan::ExternalProverKey spartan_key{
        .circuit_metadata = common.relation.circuit_metadata,
        .setup_digest = state.spartan_setup_digest,
        .pcs_scheme = common.pcs->scheme_identifier(),
        .options = {.matrix_evaluation =
                        spartan::MatrixEvaluationMode::CommittedFactored},
        .factored_computation = std::move(factored_prover),
    };
    spartan::validate_external_prover_key(spartan_key, *common.pcs);
    TranscriptPackingExternalProverSetup transcript =
        make_transcript_packing_external_prover_setup(
            state.variant, state.bhip_round_count,
            std::move(common.relation), common.pcs,
            std::move(spartan_key));
    PackedExternalProverSetup prover =
        state.variant == PackingGkrVariant::Folded
            ? make_folded_packed_external_prover_setup(
                  opened.workload.payload(), opened.workload.circuit(),
                  opened.workload.public_setup(), common.ingress,
                  std::move(transcript))
            : make_laned_packed_external_prover_setup(
                  opened.workload.payload(), opened.workload.circuit(),
                  opened.workload.public_setup(), common.ingress,
                  std::move(transcript));
    return OpenedPackedServerRoleCore{
        .publication = std::move(opened),
        .role_static = std::move(state),
        .prover_setup = std::move(prover),
    };
}

OpenedPackedClientRoleCore open_packed_client_role_core(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &client_directory,
    const Digest &expected_root_storage_identity,
    const Digest &expected_fhe_context_storage_id,
    const PackedRolePreprocessingOpenLimits &limits) {
    OpenedPackedRolePreprocessing opened =
        open_packed_client_preprocessing(
            shared_directory, client_directory,
            expected_root_storage_identity, limits.storage);
    PackedRoleStatic state = open_role_static(
        opened, PackedPreprocessingRole::Client, limits.role_static);
    RestoredCommon common = restore_common(
        opened, state, expected_fhe_context_storage_id);
    TranscriptPackingSpartanVerifierSetup verifier =
        make_verifier_setup(state, common);
    return OpenedPackedClientRoleCore{
        .publication = std::move(opened),
        .role_static = std::move(state),
        .verifier_setup = std::move(verifier),
    };
}

PackedRolePreprocessingCoreResult publish_packed_role_preprocessing_core(
    const CertifiedPackedWorkloadStatic &workload,
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    packing::ProofOfPackingR1csEncoders encoders,
    const Digest &fhe_context_storage_id,
    PackedRolePreprocessingDirectories directories,
    PackedRolePreprocessingPublishLimits limits) {
    const PackedRolePreprocessingPublicationPlan publication_plan =
        plan_packed_role_preprocessing_publication(
            workload, specification, fhe_context_storage_id);
    const std::uint64_t maximum_role_static = std::max(
        publication_plan.server_role_static_bytes,
        publication_plan.client_role_static_bytes);
    if (limits.storage.max_workload_bytes <
            publication_plan.workload_decode_requirements
                .max_artifact_bytes ||
        !covers_workload_decode_requirements(
            limits.storage.workload_decode,
            publication_plan.workload_decode_requirements) ||
        limits.role_static.max_encoded_bytes < maximum_role_static ||
        limits.role_static.max_ingress_layers <
            workload.circuit().layers.size() ||
        limits.role_static.max_factored_tensors <
            publication_plan.transcript_packing.factored.tensors.size() ||
        limits.role_static.max_relative_path_bytes == 0 ||
        limits.storage.max_role_artifact_bytes < maximum_role_static ||
        limits.storage.max_artifact_tree_files <
            publication_plan.server_artifacts.file_count ||
        limits.storage.max_artifact_tree_directories <
            publication_plan.server_artifacts.directory_count ||
        limits.storage.max_artifact_tree_depth < 2U ||
        limits.storage.max_artifact_tree_relative_path_bytes == 0 ||
        limits.storage.max_artifact_tree_file_bytes == 0 ||
        limits.storage.max_artifact_tree_bytes <
            publication_plan.server_artifacts.serialized_bytes) {
        throw std::invalid_argument(
            "packed role publication limits fail formula admission");
    }
    std::array<std::filesystem::path, 4> roots{
        normalize_empty_private_directory(directories.shared,
                                          "packed shared root"),
        normalize_empty_private_directory(directories.server,
                                          "packed server root"),
        normalize_empty_private_directory(directories.client,
                                          "packed client root"),
        normalize_empty_private_directory(directories.work,
                                          "packed work root"),
    };
    require_disjoint(roots);
    directories.shared = roots[0];
    directories.server = roots[1];
    directories.client = roots[2];
    directories.work = roots[3];
    PublicationTransaction transaction(
        std::vector<std::filesystem::path>(roots.begin(), roots.end()));

    const TranscriptPackingExternalPreprocessingPlan &plan =
        publication_plan.transcript_packing;
    const ConservativePackedProofIngressSchedule schedule =
        derive_conservative_packed_proof_ingress_schedule(
            specification.variant, workload.payload(), workload.circuit(),
            workload.public_setup(), specification.proof_ingress_policy);

    (void)publish_packed_workload_static_file(
        directories.shared, workload, limits.storage);
    const std::filesystem::path server_tree =
        directories.server /
        std::string(kPackedRoleArtifactTreeDirectory);
    const std::filesystem::path client_tree =
        directories.client /
        std::string(kPackedRoleArtifactTreeDirectory);
    make_private_directory(server_tree);
    make_private_directory(client_tree);
    const std::filesystem::path tensor_columns =
        server_tree /
        std::string(kPackedServerTensorColumnsRelativePath);
    make_private_directory(tensor_columns);
    const std::filesystem::path staging = directories.work / "staging";
    const std::filesystem::path quarantine =
        directories.work / "staging-quarantine";
    make_private_directory(staging);
    make_private_directory(quarantine);

    TranscriptPackingExternalPreprocessingResources resources{
        .staging_directory = staging,
        .canonical_tensor_directory = tensor_columns,
        .staging_quarantine_directory = quarantine,
    };
    for (std::size_t tensor = 0; tensor < plan.factored.tensors.size();
         ++tensor) {
        const std::filesystem::path state =
            server_tree /
            packed_server_basefold_state_relative_path(tensor);
        const std::filesystem::path scratch =
            directories.work /
            ("basefold-scratch-" + std::to_string(tensor));
        make_private_directory(state);
        make_private_directory(scratch);
        resources.tensors.push_back({state, scratch});
    }

    PackedRoleStatic server_static;
    PackedRoleStatic client_static;
    TranscriptPackingExternalPreprocessingReport setup_report;
    {
        TranscriptPackingExternalPreprocessing live =
            preprocess_transcript_packing_external(
                specification, std::move(encoders), resources,
                limits.transcript_packing);
        const auto &factored =
            live.verifier.spartan.factored_computation;
        if (factored == nullptr ||
            live.verifier.spartan.setup_digest !=
                live.prover.spartan_key().setup_digest) {
            throw std::logic_error(
                "packed role setup produced inconsistent Spartan keys");
        }
        server_static = make_role_static(
            PackedPreprocessingRole::Server, workload, specification,
            schedule, factored->commitment,
            live.verifier.spartan.setup_digest,
            fhe_context_storage_id);
        client_static = make_role_static(
            PackedPreprocessingRole::Client, workload, specification,
            schedule, factored->commitment,
            live.verifier.spartan.setup_digest,
            fhe_context_storage_id);
        setup_report = std::move(live.report);
    }
    // The live preprocessing result and all absolute artifact handles have
    // been destroyed. Only files at their final role-relative paths remain.
    for (const auto &entry :
         std::filesystem::directory_iterator(directories.work)) {
        if (!std::filesystem::is_directory(entry.symlink_status()) ||
            !std::filesystem::is_empty(entry.path())) {
            throw std::runtime_error(
                "packed role setup left nonempty transient storage");
        }
        std::filesystem::remove(entry.path());
    }
    if (!std::filesystem::is_empty(directories.work)) {
        throw std::runtime_error(
            "packed role setup did not retire its work tree");
    }

    write_role_static_file(
        directories.server, server_static, limits.role_static);
    write_role_static_file(
        directories.client, client_static, limits.role_static);
    (void)publish_packed_role_manifest(
        directories.server, PackedPreprocessingRole::Server,
        workload.semantic_identity(), server_static.semantic_identity,
        role_tree_semantic_identity(server_static), limits.storage);
    (void)publish_packed_role_manifest(
        directories.client, PackedPreprocessingRole::Client,
        workload.semantic_identity(), client_static.semantic_identity,
        role_tree_semantic_identity(client_static), limits.storage);
    PackedRootManifest root = publish_packed_preprocessing_root(
        directories.shared, directories.server, directories.client,
        workload, limits.storage);

    // Reopen both roles only after the root publication point binds their
    // completed manifests.
    const PackedRolePreprocessingOpenLimits opening =
        packed_role_preprocessing_open_limits(limits);
    Digest client_setup_digest{};
    spartan::FactoredMatrixCommitment client_factored_commitment;
    Digest client_workload_identity{};
    {
        OpenedPackedClientRoleCore client =
            open_packed_client_role_core(
                directories.shared, directories.client,
                root.storage_identity, fhe_context_storage_id, opening);
        client_setup_digest = client.verifier_setup.spartan.setup_digest;
        client_factored_commitment =
            client.role_static.factored_commitment;
        client_workload_identity =
            client.publication.workload.semantic_identity();
    }
    {
        OpenedPackedServerRoleCore server =
            open_packed_server_role_core(
                directories.shared, directories.server,
                root.storage_identity, fhe_context_storage_id, opening);
        if (server.prover_setup.transcript_packing()
                    .spartan_key().setup_digest != client_setup_digest ||
            server.role_static.factored_commitment !=
                client_factored_commitment ||
            server.publication.workload.semantic_identity() !=
                client_workload_identity) {
            throw std::logic_error(
                "reopened packed role states do not share one proof setup");
        }
    }
    transaction.commit();
    return PackedRolePreprocessingCoreResult{
        .root = std::move(root),
        .transcript_packing_report = std::move(setup_report),
    };
}

} // namespace detail
} // namespace laminate::protocol
