#ifndef LAMINATE_PAYLOAD_CHECKPOINT_ARTIFACT_IO_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_ARTIFACT_IO_HPP

/// @file artifact_io.hpp
/// @brief Checked arithmetic, geometry, and private artifact primitives.

#include "laminate/payload/evaluation/affine_program.hpp"
#include "laminate/payload/checkpoint/execution_types.hpp"
#include "laminate/payload/evaluation/fhe_evaluation_plan.hpp"
#include "laminate/payload/setup/encoding.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <locale>
#include <span>
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

namespace laminate::payload {

namespace checkpoint_replay_execution_detail {

inline std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                                 const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

inline std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                                 const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

inline std::uint64_t checked_count(std::size_t value, const char *label) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(label) +
                                      " does not fit u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

inline void accumulate(std::uint64_t &target, std::uint64_t value,
                       const char *label) {
    target = checked_add(target, value, label);
}

inline bool same_profile(const PayloadCheckpointStorageProfile &left,
                         const PayloadCheckpointStorageProfile &right) {
    return left.checkpoint_layers == right.checkpoint_layers &&
           left.checkpoint_metadata_bytes ==
               right.checkpoint_metadata_bytes &&
           left.checkpoint_bytes == right.checkpoint_bytes &&
           left.chunk_ciphertexts == right.chunk_ciphertexts &&
           left.dense_multiplication_alias_cache_peak_resident_bytes ==
               right.dense_multiplication_alias_cache_peak_resident_bytes &&
           left.forward_artifact_peak == right.forward_artifact_peak &&
           left.forward_peak_live_scratch_bytes ==
               right.forward_peak_live_scratch_bytes &&
           left.proof_ingress_artifact_bytes_upper_bound ==
               right.proof_ingress_artifact_bytes_upper_bound &&
           left.proof_ingress_peak_live_scratch_bytes ==
               right.proof_ingress_peak_live_scratch_bytes &&
           left.proof_ingress_peak_resident_bytes ==
               right.proof_ingress_peak_resident_bytes &&
           left.post_replay_consumer_artifact_bytes_upper_bound ==
               right.post_replay_consumer_artifact_bytes_upper_bound &&
           left.post_replay_consumer_peak_live_scratch_bytes ==
               right.post_replay_consumer_peak_live_scratch_bytes &&
           left.peak_live_scratch_bytes ==
               right.peak_live_scratch_bytes &&
           left.retained_output_peak_resident_bytes ==
               right.retained_output_peak_resident_bytes &&
           left.checkpoint_metadata_validation_buffer_bytes ==
               right.checkpoint_metadata_validation_buffer_bytes &&
           left.peak_resident_bytes == right.peak_resident_bytes &&
           left.initial_forward_work_units ==
               right.initial_forward_work_units &&
           left.replay_work_units == right.replay_work_units &&
           left.cumulative_work_units == right.cumulative_work_units &&
           left.live_scratch_feasible == right.live_scratch_feasible &&
           left.resident_feasible == right.resident_feasible &&
           left.recomputation_feasible == right.recomputation_feasible;
}

inline void require_admitted_plan(
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    const PayloadCheckpointReplayPlan &supplied) {
    const PayloadCheckpointReplayPlan admitted =
        plan_payload_checkpoint_replay(problem, budgets);
    if (!same_profile(supplied.full_trace_reference,
                      admitted.full_trace_reference) ||
        !same_profile(supplied.selected, admitted.selected) ||
        supplied.reverse_gkr_segments != admitted.reverse_gkr_segments ||
        supplied.used_nonpreferred_checkpoint !=
            admitted.used_nonpreferred_checkpoint) {
        throw std::invalid_argument(
            "checkpoint replay execution requires the admitted plan for "
            "the supplied problem and budgets");
    }
}

inline std::filesystem::path validate_empty_root(
    const std::filesystem::path &directory) {
    if (directory.empty() || !std::filesystem::exists(directory) ||
        !std::filesystem::is_directory(directory) ||
        std::filesystem::is_symlink(
            std::filesystem::symlink_status(directory)) ||
        !std::filesystem::is_empty(directory)) {
        throw std::invalid_argument(
            "checkpoint replay directory must be an existing empty "
            "non-symlink directory");
    }
    return std::filesystem::weakly_canonical(
        std::filesystem::absolute(directory));
}

inline std::string layer_directory_name(std::size_t layer) {
    std::ostringstream name;
    name.imbue(std::locale::classic());
    name << "layer-" << std::setw(16) << std::setfill('0') << layer;
    return name.str();
}

inline void append_u64(std::vector<std::uint8_t> &bytes,
                       std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        bytes.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

inline Digest layer_trace_id(const Digest &trace_id, std::size_t layer) {
    std::vector<std::uint8_t> identity;
    constexpr char kDomain[] =
        "LaminateImpl/PayloadCheckpointLayer/v1";
    identity.insert(identity.end(), kDomain, kDomain + sizeof(kDomain) - 1U);
    identity.insert(identity.end(), trace_id.begin(), trace_id.end());
    append_u64(identity, checked_count(layer, "checkpoint layer index"));
    return sha256(identity);
}

inline Digest laned_packed_layer_trace_id(
    const Digest &trace_id, std::size_t layer) {
    std::vector<std::uint8_t> identity;
    constexpr char kDomain[] =
        "LaminateImpl/PayloadCheckpointLanedPackedLayer/v1";
    identity.insert(identity.end(), kDomain,
                    kDomain + sizeof(kDomain) - 1U);
    identity.insert(identity.end(), trace_id.begin(), trace_id.end());
    append_u64(identity,
               checked_count(layer, "Laned packed layer index"));
    return sha256(identity);
}

inline void validate_execution_geometry(
    const LayeredCircuit &circuit, const FheEvaluationPlan &evaluation,
    const PayloadCheckpointReplayProblem &problem,
    const CanonicalTraceLayout &layout) {
    circuit.validate();
    evaluation.validate(circuit);
    problem.validate();
    const std::uint64_t canonical_identity_fixed =
        checkpoint_replay_metadata_identity_bytes(0);
    const std::uint64_t canonical_identity_per_layer =
        checkpoint_replay_metadata_identity_bytes(1) -
        canonical_identity_fixed;
    if (problem.checkpoint_validation_identity_fixed_bytes !=
            canonical_identity_fixed ||
        problem.checkpoint_validation_identity_bytes_per_layer !=
            canonical_identity_per_layer) {
        throw std::invalid_argument(
            "checkpoint replay execution metadata identity accounting "
            "does not match the canonical format");
    }
    if (problem.layers.size() != circuit.layers.size()) {
        throw std::invalid_argument(
            "checkpoint replay execution layer count mismatch");
    }
    const std::vector<LayerWireSupport> &support = layout.wire_support;
    const std::vector<LayerStorageLayout> &storage = layout.storage;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const PayloadReplayLayer &resource = problem.layers[layer];
        const auto *affine = std::get_if<AffineLayer>(&circuit.layers[layer]);
        const std::uint64_t expected_affine_workspace = affine == nullptr ? 0 :
            affine_program_workspace_bytes(*affine,
                storage[layer + 1U].padded_wire_count,
                storage[layer].representative_padded_indices,
                problem.layers[layer + 1U].resident_ciphertext_bytes);
        if (resource.affine_workspace_bytes != expected_affine_workspace ||
            resource.kind != layer_kind(circuit.layers[layer]) ||
            resource.stored_value_count !=
                storage[layer].stored_wire_count ||
            resource.virtual_wire_count !=
                support[layer].padded_wire_count ||
            resource.semantic_live_value_count !=
                support[layer].live_wire_count ||
            evaluation.trace.required_mult_depth_by_layer[layer] ==
                std::numeric_limits<std::size_t>::max() ||
            resource.rns_limb_count !=
                evaluation.trace.required_mult_depth_by_layer[layer] + 1U ||
            resource.required_proof_depth !=
                evaluation.proof_ingress_mult_depth_by_layer[layer] ||
            resource.modulus_switches_after_layer !=
                evaluation.modulus_switches_after_layer[layer]) {
            throw std::invalid_argument(
                "checkpoint replay execution geometry mismatch");
        }
    }
    validate_executable_checkpoint_artifact_accounting(problem);
}

inline void validate_execution_geometry(
    const LayeredCircuit &circuit, const FheEvaluationPlan &evaluation,
    const PayloadCheckpointReplayProblem &problem) {
    const CanonicalTraceLayout layout = canonical_trace_layout(circuit);
    validate_execution_geometry(circuit, evaluation, problem, layout);
}

inline std::vector<std::size_t> gate_sources(const Layer &layer,
                                             std::size_t gate_index,
                                             std::size_t source_size) {
    std::vector<std::size_t> result;
    if (const auto *affine = std::get_if<AffineLayer>(&layer)) {
        const AffineGate &gate = affine->gates.at(gate_index);
        for (const AffineTerm &term : gate.terms) {
            if (!term.coefficient.is_zero()) {
                result.push_back(term.source);
            }
        }
    } else if (const auto *multiplication =
                   std::get_if<MultiplicationLayer>(&layer)) {
        const MultiplicationGate &gate =
            multiplication->gates.at(gate_index);
        result.push_back(gate_index);
        if (gate.origin == GateOrigin::Payload) {
            result.push_back(
                multiplication->dimensions.padded_size + gate_index);
        }
    } else {
        throw std::invalid_argument(
            "checkpoint replay cannot evaluate an input layer");
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    if (!result.empty() && result.back() >= source_size) {
        throw std::invalid_argument(
            "checkpoint replay relation has an invalid source index");
    }
    return result;
}

inline std::vector<std::size_t> stored_gate_sources(
    const Layer &layer, std::size_t gate_index,
    const LayerStorageLayout &source_storage) {
    std::vector<std::size_t> result = gate_sources(
        layer, gate_index, source_storage.padded_wire_count);
    for (std::size_t &padded_index : result) {
        const std::optional<std::size_t> stored =
            source_storage.stored_ordinal_of(padded_index);
        padded_index = stored.value_or(
            std::numeric_limits<std::size_t>::max());
    }
    std::erase(result, std::numeric_limits<std::size_t>::max());
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

inline void merge_sources(std::vector<std::size_t> &target,
                          std::span<const std::size_t> additions) {
    std::vector<std::size_t> merged;
    merged.reserve(target.size() + additions.size());
    std::set_union(target.begin(), target.end(), additions.begin(),
                   additions.end(), std::back_inserter(merged));
    target = std::move(merged);
}

struct OwnedDirectoryIdentity {
#ifndef _WIN32
    std::uintmax_t device = 0;
    std::uintmax_t inode = 0;
#endif
};

inline OwnedDirectoryIdentity owned_directory_identity(
    const std::filesystem::path &path) {
#ifndef _WIN32
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0 || !S_ISDIR(status.st_mode)) {
        throw std::runtime_error(
            "checkpoint layer directory changed after creation");
    }
    return OwnedDirectoryIdentity{
        static_cast<std::uintmax_t>(status.st_dev),
        static_cast<std::uintmax_t>(status.st_ino)};
#else
    if (!std::filesystem::is_directory(
            std::filesystem::symlink_status(path))) {
        throw std::runtime_error(
            "checkpoint layer directory changed after creation");
    }
    return {};
#endif
}

inline bool same_owned_directory_noexcept(
    const std::filesystem::path &path,
    const OwnedDirectoryIdentity &expected) noexcept {
    std::error_code ignored;
    const std::filesystem::file_status link_status =
        std::filesystem::symlink_status(path, ignored);
    if (ignored || !std::filesystem::is_directory(link_status) ||
        std::filesystem::is_symlink(link_status)) {
        return false;
    }
#ifndef _WIN32
    struct stat status {};
    return ::lstat(path.c_str(), &status) == 0 && S_ISDIR(status.st_mode) &&
           expected.device ==
               static_cast<std::uintmax_t>(status.st_dev) &&
           expected.inode == static_cast<std::uintmax_t>(status.st_ino);
#else
    // Windows has no portable inode accessor in std::filesystem. The root is
    // contractually private; cleanup remains nonrecursive and refuses links.
    return true;
#endif
}

inline void write_file_exclusive(
    const std::filesystem::path &path,
    std::span<const std::uint8_t> bytes) {
#ifndef _WIN32
    int descriptor = ::open(
        path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        throw std::filesystem::filesystem_error(
            "failed to create checkpoint metadata exclusively", path,
            std::error_code(errno, std::generic_category()));
    }
    std::size_t offset = 0;
    try {
        while (offset < bytes.size()) {
            const ssize_t written = ::write(
                descriptor, bytes.data() + offset, bytes.size() - offset);
            if (written <= 0) {
                throw std::filesystem::filesystem_error(
                    "failed to write checkpoint metadata", path,
                    std::error_code(errno, std::generic_category()));
            }
            offset += static_cast<std::size_t>(written);
        }
        const int close_result = ::close(descriptor);
        descriptor = -1;
        if (close_result != 0) {
            throw std::filesystem::filesystem_error(
                "failed to close checkpoint metadata", path,
                std::error_code(errno, std::generic_category()));
        }
    } catch (...) {
        if (descriptor >= 0) {
            (void)::close(descriptor);
        }
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        throw;
    }
#else
    if (std::filesystem::exists(path)) {
        throw std::filesystem::filesystem_error(
            "checkpoint metadata target already exists", path,
            std::make_error_code(std::errc::file_exists));
    }
    std::ofstream output(path, std::ios::binary | std::ios::out);
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.close();
    if (!output) {
        throw std::runtime_error(
            "failed to write checkpoint metadata");
    }
#endif
}

/// Open and validate the file handle itself. On POSIX this rejects symlinks
/// and non-regular files before allocating the caller-admitted payload, then
/// keeps all reads bound to that inode even if the pathname is replaced.
inline std::vector<std::uint8_t> read_regular_file_no_follow_exact(
    const std::filesystem::path &path, std::size_t expected_size) {
    std::vector<std::uint8_t> bytes;
#ifndef _WIN32
    int descriptor =
        ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        throw std::filesystem::filesystem_error(
            "failed to open checkpoint metadata without following links",
            path, std::error_code(errno, std::generic_category()));
    }
    try {
        struct stat status {};
        if (::fstat(descriptor, &status) != 0 ||
            !S_ISREG(status.st_mode) || status.st_size < 0 ||
            static_cast<std::uint64_t>(status.st_size) != expected_size) {
            throw std::runtime_error(
                "checkpoint-set metadata handle changed after publication");
        }
        bytes.resize(expected_size);
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const std::size_t remaining = bytes.size() - offset;
            const std::size_t request = std::min<std::size_t>(
                remaining,
                static_cast<std::size_t>(
                    std::numeric_limits<ssize_t>::max()));
            const ssize_t received =
                ::read(descriptor, bytes.data() + offset, request);
            if (received < 0 && errno == EINTR) {
                continue;
            }
            if (received <= 0) {
                throw std::runtime_error(
                    "checkpoint-set metadata ended during validation");
            }
            offset += static_cast<std::size_t>(received);
        }
        std::uint8_t trailing = 0;
        ssize_t received = 0;
        do {
            received = ::read(descriptor, &trailing, 1);
        } while (received < 0 && errno == EINTR);
        if (received != 0) {
            throw std::runtime_error(
                "checkpoint-set metadata grew during validation");
        }
        const int close_result = ::close(descriptor);
        descriptor = -1;
        if (close_result != 0) {
            throw std::filesystem::filesystem_error(
                "failed to close checkpoint metadata", path,
                std::error_code(errno, std::generic_category()));
        }
    } catch (...) {
        if (descriptor >= 0) {
            (void)::close(descriptor);
        }
        throw;
    }
#else
    if (!std::filesystem::is_regular_file(
            std::filesystem::symlink_status(path)) ||
        std::filesystem::file_size(path) != expected_size ||
        expected_size >
            static_cast<std::size_t>(
                std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error(
            "checkpoint-set metadata path changed after publication");
    }
    bytes.resize(expected_size);
    std::ifstream input(path, std::ios::binary);
    input.read(reinterpret_cast<char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (!input || input.peek() != std::ifstream::traits_type::eof()) {
        throw std::runtime_error(
            "checkpoint-set metadata changed during validation");
    }
#endif
    return bytes;
}

inline void publish_file_no_replace(
    const std::filesystem::path &staged,
    const std::filesystem::path &final) {
    if (!std::filesystem::is_regular_file(
            std::filesystem::symlink_status(staged))) {
        throw std::runtime_error(
            "checkpoint metadata staging file is not regular");
    }
    // A hard link is an atomic, same-device, no-replace publication. The
    // caller-owned private directory makes the subsequent unlink safe.
    std::filesystem::create_hard_link(staged, final);
    if (!std::filesystem::is_regular_file(
            std::filesystem::symlink_status(final)) ||
        std::filesystem::file_size(final) !=
            std::filesystem::file_size(staged)) {
        throw std::runtime_error(
            "checkpoint metadata changed during publication");
    }
    if (!std::filesystem::remove(staged)) {
        throw std::runtime_error(
            "failed to remove checkpoint metadata staging link");
    }
}

inline std::size_t minimum_relation_chunk_ciphertexts(
    const LayeredCircuit &circuit,
    std::span<const LayerStorageLayout> storage) {
    std::size_t minimum = 1;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (!std::holds_alternative<MultiplicationLayer>(
                circuit.layers[layer])) {
            continue;
        }
        const LayerStorageLayout &source_storage = storage[layer + 1U];
        for (std::size_t gate :
             storage[layer].representative_padded_indices) {
            minimum = std::max(
                minimum,
                stored_gate_sources(circuit.layers[layer], gate,
                                    source_storage)
                    .size());
        }
    }
    return minimum;
}

} // namespace checkpoint_replay_execution_detail

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_CHECKPOINT_ARTIFACT_IO_HPP
