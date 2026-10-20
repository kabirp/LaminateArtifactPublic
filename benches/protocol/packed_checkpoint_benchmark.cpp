/// @file packed_checkpoint_benchmark.cpp
/// @brief Role-separated, real-SEAL Folded/Laned process benchmark.
///
/// Setup fixes the workload, exact modulus schedule, and packed-proof profile
/// and publishes reusable role state. Online execution evaluates the payload,
/// consumes checkpoint/replay state for GKR, and completes external transcript
/// packing before publishing one response. Phase timing fields distinguish
/// reusable startup, recurring work, peer waiting, and post-verification audits.
/// The quick profile uses reduced repetitions and a diagnostic commitment;
/// successful execution does not promote it to the target integrity parameters.

#include "benchmark_support.hpp"
#include "gate_mle_report_policy.hpp"
#include "client_computation.hpp"
#include "completed_result_report.hpp"
#include "packed_checkpoint_git_state.hpp"
#include "protocol_progress.hpp"
#include "run_lifecycle_lock.hpp"
#include "setup_execution.hpp"
#include "folded_target_noise_preflight.hpp"

#include "laminate/bench/packed_checkpoint_replay.hpp"
#include "laminate/bench/packed_checkpoint_policy.hpp"
#include "laminate/bench/packed_process_profile.hpp"
#include "laminate/bench/packed_setup_admission.hpp"
#include "laminate/basefold/soundness.hpp"
#include "laminate/delegation/laned/client.hpp"
#include "laminate/delegation/folded/client.hpp"
#include "laminate/delegation/folded/profiling/client.hpp"
#include "laminate/delegation/folded/server.hpp"
#include "laminate/delegation/folded/wire/codec.hpp"
#include "laminate/delegation/laned/profiling/client.hpp"
#include "laminate/delegation/laned/wire/codec.hpp"
#include "laminate/delegation/packed/client.hpp"
#include "laminate/delegation/laned/server.hpp"
#include "laminate/delegation/laned/wire/format.hpp"
#include "laminate/field/fq_ntt.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/gkr/detail/laned/affine/source/chunk_batches.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/resource_bounds.hpp"
#include "laminate/payload/checkpoint/plan.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/protocol/packed/preprocessing/roles.hpp"
#include "laminate/protocol/packed/online/server.hpp"
#include "laminate/protocol/packed/wire/proof.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"
#include "laminate/protocol/fiat_shamir.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sched.h>
#endif

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::packing;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

constexpr std::string_view kSetupDomain =
    "LaminateImpl/PackedCheckpointProcessSetup/v7";
constexpr std::uint64_t kSetupVersion = 14;
constexpr std::string_view kProcessTranscriptDomain =
    "LaminateImpl/PackedCheckpointProcessTranscript/v2";
constexpr std::size_t kMaximumSetupRecordBytes = 8U << 20U;
constexpr std::uint64_t kPackedRoleManifestMaxBytes = 8ULL << 20U;
constexpr std::size_t kIoBlockElements = 1U << 16U;
constexpr std::size_t kBaseFoldTransformTileElements = 1U << 24U;
constexpr std::size_t kReplayChunkCiphertexts = 64;
constexpr std::uint64_t kOnlineMetadataDiskReserve = 16ULL << 20U;
constexpr std::uint64_t kPackedPublicationManifestCount = 3;
constexpr std::uint64_t kDecodedWorkloadResidentMultiplier = 4;
constexpr std::uint64_t kResidentSafetySlack = 2ULL << 30U;
constexpr std::uint64_t kCodecWorkingSlack = 512ULL << 20U;
// The client bundle contains a two-polynomial public key and a
// one-polynomial secret key at the key level. A fourth full polynomial plus
// this framing allowance conservatively covers SEAL object/envelope overhead
// and the key-free public-verifier bundle.
constexpr std::uint64_t kClientKeyPolynomialUpperBound = 4;
constexpr std::uint64_t kClientFheBundleFramingReserveBytes = 2ULL << 20U;
// Bound client role-static state before SEAL keys exist using the enforced
// setup-record byte ceiling. Verify the exact role-static plan against this
// bound before publication.
constexpr std::uint64_t kClientRoleStaticReserveBytes =
    kMaximumSetupRecordBytes;
constexpr std::uint64_t kExternalPackingBlockWorking = 512ULL << 20U;
constexpr std::uint64_t kExternalPackingWorkingPeak =
    2 * kExternalPackingBlockWorking;
constexpr std::size_t kPackedOutputMaximumCanonicalErrorNormBits = 10;
static_assert(2ULL * kBaseFoldTransformTileElements * sizeof(Fq) <=
              kExternalPackingBlockWorking);
constexpr PayloadRecomputationFactorLimit kMaximumRecomputation{5, 2};

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

/// Secret-key-assisted evidence about the encrypted payload output. This is an
/// honest-run diagnostic performed only after the protocol verifier accepts;
/// it is not part of verification and is not a completeness certificate.
struct PackedOutputNoiseAudit {
    std::size_t encrypted_ciphertext_count = 0;
    std::size_t data_rns_limb_count = 0;
    std::size_t data_modulus_product_bits = 0;
    int minimum_invariant_noise_budget_bits =
        std::numeric_limits<int>::max();
    std::size_t maximum_invariant_budget_implied_phase_norm_bits = 0;
    std::uint64_t maximum_canonical_error_norm = 0;
    std::size_t maximum_canonical_error_norm_bits = 0;
};

PackedOutputNoiseAudit audit_packed_output_noise(
    const SealBackend::ClientContext &client,
    const SealBackend::PublicVerifierContext &verifier,
    std::span<const FheValue<SealBackend>> output_values,
    std::size_t expected_encrypted_ciphertexts) {
    PackedOutputNoiseAudit result;

    for (const FheValue<SealBackend> &value : output_values) {
        if (value.is_public()) {
            continue;
        }

        const SealBackend::Ciphertext &ciphertext = value.ciphertext();
        const std::vector<std::uint64_t> moduli =
            SealBackend::data_coefficient_moduli(client, ciphertext);
        require(moduli.size() == 1,
                "packed payload output did not reach one data RNS prime");
        require(moduli.front() == kOuterFieldOrder,
                "packed payload output did not reach q0=Q");

        const std::size_t modulus_bits =
            NaturalMagnitude::product(moduli).bit_count();
        const int budget =
            SealBackend::invariant_noise_budget(client, ciphertext);
        require(budget >= 0 && static_cast<std::size_t>(budget) < modulus_bits,
                "packed payload output returned an invalid invariant-noise "
                "budget");

        if (result.encrypted_ciphertext_count == 0) {
            result.data_rns_limb_count = moduli.size();
            result.data_modulus_product_bits = modulus_bits;
        } else {
            require(result.data_rns_limb_count == moduli.size() &&
                        result.data_modulus_product_bits == modulus_bits,
                    "packed payload outputs disagree on their final data "
                    "modulus");
        }
        ++result.encrypted_ciphertext_count;
        result.minimum_invariant_noise_budget_bits =
            std::min(result.minimum_invariant_noise_budget_bits, budget);
        result.maximum_invariant_budget_implied_phase_norm_bits = std::max(
            result.maximum_invariant_budget_implied_phase_norm_bits,
            modulus_bits - static_cast<std::size_t>(budget) - 1U);
        const std::uint64_t canonical_error =
            SealBackend::canonical_error_infinity_norm(
                verifier, client, ciphertext);
        result.maximum_canonical_error_norm = std::max(
            result.maximum_canonical_error_norm, canonical_error);
        result.maximum_canonical_error_norm_bits = std::max(
            result.maximum_canonical_error_norm_bits,
            static_cast<std::size_t>(std::bit_width(canonical_error)));
    }

    require(result.encrypted_ciphertext_count ==
                expected_encrypted_ciphertexts,
            "packed payload output ciphertext count changed before the "
            "honest-noise audit");
    return result;
}

bool packed_output_noise_target_passes(
    const PackedOutputNoiseAudit &audit) {
    return audit.maximum_canonical_error_norm_bits <=
           kPackedOutputMaximumCanonicalErrorNormBits;
}

void require_packed_output_noise_target(
    const PackedOutputNoiseAudit &audit) {
    if (!packed_output_noise_target_passes(audit)) {
        throw std::runtime_error(
            "packed payload output canonical error is " +
            std::to_string(audit.maximum_canonical_error_norm) +
            " (" +
            std::to_string(audit.maximum_canonical_error_norm_bits) +
            " bits), exceeding the 10-bit honest canonical-error target; "
            "minimum invariant noise budget was " +
            std::to_string(audit.minimum_invariant_noise_budget_bits) +
            " bits");
    }
}

void emit_seal_operation_counts(
    const Record &record, std::string_view stage,
    const SealBackend::OperationCounts &counts) {
    const std::string prefix = "operations." + std::string(stage) + '.';
    for (std::size_t index = 0;
         index < static_cast<std::size_t>(SealBackend::OperationKind::Count);
         ++index) {
        const auto kind = static_cast<SealBackend::OperationKind>(index);
        const std::string operation = SealBackend::operation_name(kind);
        record.integer(prefix + operation + ".calls", counts.calls(kind));
        record.integer(prefix + operation + ".limb_operations",
                       counts.limb_operations(kind));
        std::vector<std::string> buckets;
        for (const auto &[limbs, calls] : counts.buckets(kind)) {
            buckets.push_back(std::to_string(limbs) + ':' +
                              std::to_string(calls));
        }
        record.text(prefix + operation + ".by_rns_limb",
                    buckets.empty() ? "none" : join(buckets));
    }
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          std::string_view label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply(std::uint64_t left, std::uint64_t right,
                               std::string_view label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows");
    }
    return left * right;
}

std::size_t checked_size(std::uint64_t value, std::string_view label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

enum class ProcessAction : std::uint8_t {
    Setup,
    RunClient,
    RunServer,
    AuditOutput,
    Status,
};

struct ProcessCommand {
    ProcessAction action = ProcessAction::Status;
    PackedProcessVariant variant = PackedProcessVariant::Folded;
    PackedProcessTier tier = PackedProcessTier::Quick;
    std::string variant_name;
    std::string profile_name;
    std::size_t lanes = 0;
    std::filesystem::path run_directory;
};

bool is_process_action(std::string_view value) {
    return value == "setup" || value == "run_client" ||
           value == "run_server" || value == "audit_output" ||
           value == "status";
}

ProcessCommand parse_process_command(int argc, char **argv) {
    if ((argc != 8 && argc != 10) || !is_process_action(argv[1]) ||
        std::string_view(argv[2]) != "--variant" ||
        std::string_view(argv[4]) != "--profile" ||
        std::string_view(argv[6]) != "--run-dir") {
        throw std::invalid_argument(
            "expected ACTION (setup, run_client, run_server, audit_output, "
            "or status) --variant folded|laned --profile "
            "quick|target-balancedLaned|target-mulHeavyPyramid --run-dir ABSOLUTE_PATH "
            "[--lanes 1|128|16384]");
    }
    ProcessCommand result;
    const std::string_view action(argv[1]);
    result.action = action == "setup"       ? ProcessAction::Setup
                    : action == "run_client" ? ProcessAction::RunClient
                    : action == "run_server" ? ProcessAction::RunServer
                    : action == "audit_output" ? ProcessAction::AuditOutput
                                                 : ProcessAction::Status;
    result.variant_name = argv[3];
    result.profile_name = argv[5];
    if (result.variant_name == "folded") {
        result.variant = PackedProcessVariant::Folded;
        if (argc != 8) {
            throw std::invalid_argument(
                "--lanes is valid only for the laned variant");
        }
    } else if (result.variant_name == "laned") {
        result.variant = PackedProcessVariant::Laned;
        if (argc != 10 || std::string_view(argv[8]) != "--lanes") {
            throw std::invalid_argument(
                "the laned variant requires --lanes 1, 128, or 16384");
        }
        const std::string_view lane_count(argv[9]);
        result.lanes = lane_count == "1"       ? 1
                       : lane_count == "128"   ? 128
                       : lane_count == "16384" ? kDefaultPolyModulusDegree
                                                 : 0;
        if (result.lanes == 0) {
            throw std::invalid_argument(
                "the laned variant requires --lanes 1, 128, or 16384");
        }
    } else {
        throw std::invalid_argument("variant must be folded or laned");
    }
    result.tier = benchmark_payload_tier(result.profile_name);
    if ((result.action == ProcessAction::Setup ||
         result.action == ProcessAction::RunClient ||
         result.action == ProcessAction::RunServer) &&
        !benchmark_profile_is_in_campaign(result.variant_name, result.tier)) {
        throw std::invalid_argument(
            "current benchmark campaign permits Folded on both target profiles "
            "and Laned on target-balancedLaned; quick diagnostics remain available");
    }
    result.run_directory = argv[7];
    if (!result.run_directory.is_absolute() ||
        result.run_directory == result.run_directory.root_path()) {
        throw std::invalid_argument(
            "--run-dir must be an absolute path below the filesystem root");
    }
    return result;
}

struct ProcessCapacity {
    std::uint64_t max_live_disk_bytes = 0;
    std::uint64_t max_resident_ram_bytes = 0;
    std::uint64_t min_free_disk_bytes = 0;

    bool operator==(const ProcessCapacity &) const = default;
};

ProcessCapacity process_capacity(const HostResourceBudget &budget) {
    if (derive_host_resource_budget(
            budget.observed_available_disk_bytes,
            budget.observed_physical_ram_bytes) != budget) {
        throw std::invalid_argument(
            "process capacity has a noncanonical host budget");
    }
    return {budget.max_live_disk_bytes, budget.max_resident_ram_bytes,
            kBenchmarkFreeDiskReserveBytes};
}

ProcessCapacity process_capacity(
    const HostResourceBudget &budget,
    std::uint64_t client_private_persistent_bytes,
    std::uint64_t client_peak_resident_bytes) {
    ProcessCapacity result = process_capacity(budget);
    result.max_live_disk_bytes = reserve_role_private_disk(
        budget, client_private_persistent_bytes);
    result.max_resident_ram_bytes = reserve_concurrent_client_ram(
        budget, client_peak_resident_bytes);
    return result;
}

std::uint64_t conservative_adaptive_client_fhe_bundle_bytes(
    const PackedProcessProfile &profile) {
    const std::uint64_t key_rns_limbs = checked_add(
        profile.fresh_rns_limbs(), 1,
        "packed client key RNS limbs");
    const std::uint64_t key_coefficients = checked_multiply(
        checked_multiply(kClientKeyPolynomialUpperBound, profile.slots,
                         "packed client key coefficients"),
        key_rns_limbs, "packed client key coefficients");
    return checked_add(
        checked_multiply(key_coefficients, sizeof(std::uint64_t),
                         "packed client key bytes"),
        kClientFheBundleFramingReserveBytes,
        "packed client FHE bundle reserve");
}

std::uint64_t conservative_adaptive_client_private_persistent_bytes(
    const PackedProcessProfile &profile) {
    const std::uint64_t fhe_bundle_bytes =
        conservative_adaptive_client_fhe_bundle_bytes(profile);
    return checked_add(
        fhe_bundle_bytes,
        checked_add(kClientRoleStaticReserveBytes,
                    kPackedRoleManifestMaxBytes,
                    "packed client role publication reserve"),
        "packed client-private persistence reserve");
}

void require_profile_execution_policy_before_artifacts(
    const PackedProcessProfile &profile) {
    if (profile.admits_execution()) {
        return;
    }
    throw std::runtime_error(
        "evaluation profiles require a non-diagnostic ciphertext "
        "commitment policy");
}

void make_private_directory(const std::filesystem::path &path) {
    std::error_code error;
    if (!std::filesystem::create_directory(path, error) || error) {
        throw std::runtime_error("failed to create private directory: " +
                                 path.string());
    }
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace, error);
    if (error) {
        throw std::runtime_error("failed to protect private directory: " +
                                 path.string());
    }
}

void create_run_tree(const std::filesystem::path &root) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(root, error);
    if (!error && status.type() != std::filesystem::file_type::not_found) {
        throw std::invalid_argument(
            "setup requires a run directory that does not already exist");
    }
    error.clear();
    make_private_directory(root);
    for (const std::string_view child : {"shared", "client", "server"}) {
        make_private_directory(root / child);
    }
    for (const std::string_view child :
         {"transcript", "report", "preprocessing", "setup-work"}) {
        make_private_directory(root / "shared" / child);
    }
    make_private_directory(root / "shared" / "preprocessing" /
                           "packed-shared");
    make_private_directory(root / "shared" / "setup-work" / "packed");
    for (const std::string_view role : {"client", "server"}) {
        make_private_directory(root / role / "preprocessing");
        make_private_directory(root / role / "work");
        make_private_directory(root / role / "preprocessing" /
                               (std::string("packed-") +
                                std::string(role)));
    }
}

class Writer {
  public:
    void u64(std::uint64_t value) {
        for (std::size_t byte = 0; byte < 8; ++byte) {
            bytes_.push_back(static_cast<std::uint8_t>(
                (value >> (8U * byte)) & 0xffU));
        }
    }
    void boolean(bool value) { u64(value ? 1 : 0); }
    void digest(const Digest &value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    void text(std::string_view value) {
        u64(value.size());
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    template <typename Range> void sizes(const Range &values) {
        u64(values.size());
        for (const auto value : values) {
            u64(static_cast<std::uint64_t>(value));
        }
    }
    void u64s(std::span<const std::uint64_t> values) {
        u64(values.size());
        for (const std::uint64_t value : values) {
            u64(value);
        }
    }
    std::span<const std::uint8_t> view() const { return bytes_; }
    std::vector<std::uint8_t> finish() && { return std::move(bytes_); }

  private:
    std::vector<std::uint8_t> bytes_;
};

class Reader {
  public:
    explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
    std::uint64_t u64(std::string_view label) {
        if (remaining() < 8) {
            throw std::invalid_argument(std::string(label) + " is truncated");
        }
        std::uint64_t result = 0;
        for (std::size_t byte = 0; byte < 8; ++byte) {
            result |= static_cast<std::uint64_t>(bytes_[position_++])
                      << (8U * byte);
        }
        return result;
    }
    bool boolean(std::string_view label) {
        const std::uint64_t value = u64(label);
        if (value > 1) {
            throw std::invalid_argument(std::string(label) + " is not bool");
        }
        return value != 0;
    }
    Digest digest(std::string_view label) {
        if (remaining() < Digest{}.size()) {
            throw std::invalid_argument(std::string(label) + " is truncated");
        }
        Digest result{};
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(position_),
                    result.size(), result.begin());
        position_ += result.size();
        return result;
    }
    std::string text(std::string_view label, std::size_t maximum = 256) {
        const std::size_t size = checked_size(u64(label), label);
        if (size > maximum || size > remaining()) {
            throw std::invalid_argument(std::string(label) + " is oversized");
        }
        std::string result(
            reinterpret_cast<const char *>(bytes_.data() + position_), size);
        position_ += size;
        return result;
    }
    std::vector<std::size_t> sizes(std::string_view label,
                                   std::size_t maximum = 1024) {
        const std::size_t count = checked_size(u64(label), label);
        if (count > maximum || count > remaining() / 8) {
            throw std::invalid_argument(std::string(label) + " is oversized");
        }
        std::vector<std::size_t> result;
        result.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(checked_size(u64(label), label));
        }
        return result;
    }
    std::vector<std::uint64_t> u64s(std::string_view label,
                                    std::size_t maximum = 1024) {
        const std::size_t count = checked_size(u64(label), label);
        if (count > maximum || count > remaining() / 8) {
            throw std::invalid_argument(std::string(label) + " is oversized");
        }
        std::vector<std::uint64_t> result;
        result.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(u64(label));
        }
        return result;
    }
    std::size_t remaining() const { return bytes_.size() - position_; }
    void require_end() const {
        if (remaining() != 0) {
            throw std::invalid_argument("setup record has trailing bytes");
        }
    }

  private:
    std::span<const std::uint8_t> bytes_;
    std::size_t position_ = 0;
};

struct BundleBinding {
    std::uint64_t bytes = 0;
    Digest digest{};

    bool operator==(const BundleBinding &) const = default;
};

struct ProcessSetupRecord {
    std::uint64_t codec_version = kSetupVersion;
    std::string variant;
    std::string profile;
    std::string git_commit;
    std::string build_type;
    std::string seal_acceleration;
    Digest run_id{};
    Digest root_storage_identity{};
    Digest workload_semantic_identity{};
    Digest public_setup_digest{};
    Digest circuit_digest{};
    Digest fhe_context_storage_id{};
    std::string proof_ingress_policy;
    Digest proof_ingress_schedule_digest{};

    std::uint64_t slots = 0;
    std::uint64_t lanes = 0;
    std::uint64_t multiplicative_depth = 0;
    std::uint64_t middle_width = 0;
    std::uint64_t payload_operations = 0;
    std::uint64_t input_ciphertexts = 0;
    std::uint64_t output_ciphertexts = 0;
    std::uint64_t packing_repetitions = 0;
    std::uint64_t selected_packing_repetitions = 0;
    std::uint64_t basefold_queries = 0;
    std::uint64_t selected_basefold_queries = 0;
    std::uint64_t basefold_log_rate = 0;
    std::uint64_t ciphertext_commitment_policy_code = 0;
    std::vector<int> data_prime_bit_sizes;
    std::uint64_t special_prime_bits = 0;
    std::vector<std::uint64_t> data_primes;
    std::uint64_t special_prime = 0;
    std::uint64_t fresh_modulus_product_bits = 0;
    std::uint64_t key_modulus_product_bits = 0;
    bool diagnostic_stress_only = true;

    BundleBinding evaluation_bundle;
    BundleBinding client_bundle;
    BundleBinding verifier_bundle;
    BundleBinding fixed_message_basis;
    Digest fixed_message_basis_artifact_id{};
    std::uint64_t fixed_message_basis_ntt_bytes = 0;

    std::uint64_t workload_max_bytes = 0;
    PackedWorkloadStaticDecodeLimits workload_decode;
    std::uint64_t role_static_max_bytes = 0;
    std::uint64_t manifest_max_bytes = 0;
    std::uint64_t artifact_tree_files = 0;
    std::uint64_t artifact_tree_directories = 0;
    std::uint64_t artifact_tree_file_max_bytes = 0;
    std::uint64_t artifact_tree_total_bytes = 0;
    std::uint64_t factored_tensor_count = 0;

    FheEvaluationPlan evaluation_plan;
    PayloadCheckpointReplayProblem replay_problem;
    PayloadCheckpointReplayBudgets replay_budgets;
    Digest replay_plan_digest{};

    ProcessCapacity capacity;
    HostResourceBudget host_budget;
    std::uint64_t client_private_persistent_bytes = 0;
    std::vector<std::uint64_t> multiplication_scratch_bytes_by_reduction;
    std::uint64_t request_wire_bytes = 0;
    std::uint64_t response_wire_bytes = 0;
    std::uint64_t ciphertext_wire_bytes = 0;
    std::uint64_t request_max_ciphertexts = 0;
    std::uint64_t response_max_ciphertexts = 0;
    std::uint64_t proof_max_ciphertexts = 0;
    std::uint64_t proof_max_collection_elements = 0;
    std::uint64_t proof_max_field_elements = 0;
    std::uint64_t proof_max_digests = 0;
    std::uint64_t gate_mle_retained_prover_key_bytes = 0;
    std::uint64_t gate_mle_opening_workspace_bytes = 0;
    std::uint64_t gate_mle_retained_prover_key_disk_bytes = 0;
    std::uint64_t gate_mle_opening_workspace_disk_bytes = 0;
    std::uint64_t gate_mle_affine_preparation_workspace_bytes = 0;
    std::uint64_t server_common_resident_bytes = 0;
    std::uint64_t server_payload_gkr_only_resident_bytes = 0;
    std::uint64_t server_packing_only_resident_bytes = 0;
    std::uint64_t reduction_workspace_resident_bytes = 0;
    std::uint64_t client_peak_resident_bytes = 0;
    Digest packing_preflight_digest{};
    std::uint64_t packing_persistent_overlap_bytes = 0;
    std::uint64_t packing_peak_live_bytes = 0;

};

void encode_bundle(Writer &writer, const BundleBinding &bundle) {
    writer.u64(bundle.bytes);
    writer.digest(bundle.digest);
}

BundleBinding decode_bundle(Reader &reader, std::string_view label) {
    return {reader.u64(std::string(label) + " bytes"),
            reader.digest(std::string(label) + " digest")};
}

void encode_workload_decode_limits(
    Writer &writer, const PackedWorkloadStaticDecodeLimits &limits) {
    for (const std::size_t value : {
             limits.max_artifact_bytes, limits.max_slots,
             limits.max_payload_plaintexts, limits.max_payload_gates,
             limits.max_payload_outputs, limits.max_layers,
             limits.max_layer_gates, limits.max_affine_terms,
             limits.max_storage_entries, limits.max_gate_tables}) {
        writer.u64(value);
    }
}

PackedWorkloadStaticDecodeLimits decode_workload_decode_limits(
    Reader &reader) {
    const auto size = [&reader](std::string_view label) {
        return checked_size(reader.u64(label), label);
    };
    return {
        .max_artifact_bytes = size("workload artifact decode bytes"),
        .max_slots = size("workload decode slots"),
        .max_payload_plaintexts =
            size("workload decode plaintexts"),
        .max_payload_gates = size("workload decode payload gates"),
        .max_payload_outputs =
            size("workload decode payload outputs"),
        .max_layers = size("workload decode layers"),
        .max_layer_gates = size("workload decode layer gates"),
        .max_affine_terms = size("workload decode affine terms"),
        .max_storage_entries =
            size("workload decode storage entries"),
        .max_gate_tables = size("workload decode gate tables"),
    };
}

void encode_evaluation_plan(Writer &writer,
                            const FheEvaluationPlan &plan) {
    writer.sizes(plan.trace.required_mult_depth_by_layer);
    writer.sizes(plan.proof_ingress_mult_depth_by_layer);
    writer.sizes(plan.modulus_switches_after_layer);
}

FheEvaluationPlan decode_evaluation_plan(Reader &reader) {
    return FheEvaluationPlan{
        .trace = TraceEncryptionPlan{
            reader.sizes("trace levels")},
        .proof_ingress_mult_depth_by_layer =
            reader.sizes("proof ingress levels"),
        .modulus_switches_after_layer =
            reader.sizes("modulus switches"),
    };
}

void encode_replay_problem(Writer &writer,
                           const PayloadCheckpointReplayProblem &problem) {
    writer.u64(problem.layers.size());
    for (const PayloadReplayLayer &layer : problem.layers) {
        writer.u64(layer.layer);
        writer.u64(static_cast<std::uint64_t>(layer.kind));
        writer.u64(layer.stored_value_count);
        writer.u64(layer.virtual_wire_count);
        writer.u64(layer.rns_limb_count);
        writer.u64(layer.required_proof_depth);
        writer.u64(layer.modulus_switches_after_layer);
        writer.u64(layer.checkpoint_bytes);
        writer.u64(layer.serialized_ciphertext_bytes);
        writer.u64(layer.resident_ciphertext_bytes);
        writer.u64(layer.replay_work_units);
        writer.boolean(layer.preferred_checkpoint);
        writer.u64(layer.proof_ingress_serialized_ciphertext_bytes);
        writer.u64(layer.proof_ingress_resident_ciphertext_bytes);
        writer.u64(layer.semantic_live_value_count);
        writer.u64(layer.affine_workspace_bytes);
    }
    writer.u64(problem.checkpoint_set_fixed_bytes);
    writer.u64(problem.checkpoint_set_bytes_per_layer);
    writer.u64(problem.checkpoint_validation_identity_fixed_bytes);
    writer.u64(problem.checkpoint_validation_identity_bytes_per_layer);
}

PayloadCheckpointReplayProblem decode_replay_problem(
    Reader &reader) {
    const std::size_t count = checked_size(reader.u64("replay layer count"),
                                           "replay layer count");
    if (count == 0 || count > 1024) {
        throw std::invalid_argument("replay layer count is invalid");
    }
    PayloadCheckpointReplayProblem result;
    result.layers.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto layer = reader.u64("replay layer");
        const auto kind = reader.u64("replay layer kind");
        if (kind > static_cast<std::uint64_t>(LayerKind::Input)) {
            throw std::invalid_argument("replay layer kind is invalid");
        }
        result.layers.push_back(PayloadReplayLayer{
            .layer = checked_size(layer, "replay layer"),
            .kind = static_cast<LayerKind>(kind),
            .stored_value_count = checked_size(
                reader.u64("stored values"), "stored values"),
            .virtual_wire_count = checked_size(
                reader.u64("virtual wires"), "virtual wires"),
            .rns_limb_count = checked_size(
                reader.u64("rns limbs"), "rns limbs"),
            .required_proof_depth = checked_size(
                reader.u64("proof depth"), "proof depth"),
            .modulus_switches_after_layer = checked_size(
                reader.u64("switches"), "switches"),
            .checkpoint_bytes = reader.u64("checkpoint bytes"),
            .serialized_ciphertext_bytes = reader.u64("serialized bytes"),
            .resident_ciphertext_bytes = reader.u64("resident bytes"),
            .replay_work_units = reader.u64("replay work"),
            .preferred_checkpoint = reader.boolean("preferred checkpoint"),
            .proof_ingress_serialized_ciphertext_bytes =
                reader.u64("proof serialized bytes"),
            .proof_ingress_resident_ciphertext_bytes =
                reader.u64("proof resident bytes"),
            .semantic_live_value_count = checked_size(
                reader.u64("semantic live values"),
                "semantic live values"),
            .affine_workspace_bytes = reader.u64("affine DAG workspace bytes"),
        });
    }
    result.checkpoint_set_fixed_bytes = reader.u64("checkpoint fixed bytes");
    result.checkpoint_set_bytes_per_layer =
        reader.u64("checkpoint bytes per layer");
    result.checkpoint_validation_identity_fixed_bytes =
        reader.u64("checkpoint validation fixed bytes");
    result.checkpoint_validation_identity_bytes_per_layer =
        reader.u64("checkpoint validation bytes per layer");
    return result;
}

void encode_replay_budgets(Writer &writer,
                           const PayloadCheckpointReplayBudgets &budgets) {
    writer.u64(budgets.max_live_scratch_bytes);
    writer.u64(budgets.max_resident_ciphertext_bytes);
    writer.u64(budgets.max_ciphertexts_per_chunk);
    writer.u64(budgets.max_recomputation_factor.numerator);
    writer.u64(budgets.max_recomputation_factor.denominator);
    writer.u64(budgets.reserved_live_scratch_bytes);
    writer.u64(budgets.reserved_resident_bytes);
    writer.u64(static_cast<std::uint64_t>(budgets.selection_objective));
    writer.u64s(
        budgets.post_replay_consumer_artifact_bytes_by_reduction);
}

PayloadCheckpointReplayBudgets decode_replay_budgets(Reader &reader) {
    PayloadCheckpointReplayBudgets result{
        .max_live_scratch_bytes = reader.u64("max replay scratch"),
        .max_resident_ciphertext_bytes = reader.u64("max replay resident"),
        .max_ciphertexts_per_chunk = checked_size(
            reader.u64("replay chunk"), "replay chunk"),
        .max_recomputation_factor = {
            reader.u64("recomputation numerator"),
            reader.u64("recomputation denominator")},
        .reserved_live_scratch_bytes = reader.u64("reserved replay scratch"),
        .reserved_resident_bytes = reader.u64("reserved replay resident"),
    };
    const std::uint64_t objective =
        reader.u64("replay selection objective");
    if (objective > static_cast<std::uint64_t>(
                        PayloadCheckpointSelectionObjective::
                            MinimumReplayWork)) {
        throw std::invalid_argument(
            "replay selection objective is invalid");
    }
    result.selection_objective =
        static_cast<PayloadCheckpointSelectionObjective>(objective);
    result.post_replay_consumer_artifact_bytes_by_reduction =
        reader.u64s("post-replay consumer artifact bounds");
    return result;
}

std::vector<std::uint8_t> encode_setup_body(
    const ProcessSetupRecord &record) {
    Writer writer;
    writer.text(kSetupDomain);
    writer.u64(record.codec_version);
    writer.text(record.variant);
    writer.text(record.profile);
    writer.text(record.git_commit);
    writer.text(record.build_type);
    writer.text(record.seal_acceleration);
    writer.digest(record.run_id);
    writer.digest(record.root_storage_identity);
    writer.digest(record.workload_semantic_identity);
    writer.digest(record.public_setup_digest);
    writer.digest(record.circuit_digest);
    writer.digest(record.fhe_context_storage_id);
    writer.text(record.proof_ingress_policy);
    writer.digest(record.proof_ingress_schedule_digest);
    for (const std::uint64_t value : {
             record.slots, record.lanes, record.multiplicative_depth,
             record.middle_width, record.payload_operations,
             record.input_ciphertexts,
             record.output_ciphertexts, record.packing_repetitions,
             record.selected_packing_repetitions, record.basefold_queries,
             record.selected_basefold_queries, record.basefold_log_rate,
             record.ciphertext_commitment_policy_code}) {
        writer.u64(value);
    }
    writer.sizes(record.data_prime_bit_sizes);
    writer.u64(record.special_prime_bits);
    writer.u64s(record.data_primes);
    writer.u64(record.special_prime);
    writer.u64(record.fresh_modulus_product_bits);
    writer.u64(record.key_modulus_product_bits);
    writer.boolean(record.diagnostic_stress_only);
    encode_bundle(writer, record.evaluation_bundle);
    encode_bundle(writer, record.client_bundle);
    encode_bundle(writer, record.verifier_bundle);
    encode_bundle(writer, record.fixed_message_basis);
    writer.digest(record.fixed_message_basis_artifact_id);
    writer.u64(record.fixed_message_basis_ntt_bytes);
    for (const std::uint64_t value : {
             record.workload_max_bytes, record.role_static_max_bytes,
             record.manifest_max_bytes, record.artifact_tree_files,
             record.artifact_tree_directories,
             record.artifact_tree_file_max_bytes,
             record.artifact_tree_total_bytes,
             record.factored_tensor_count}) {
        writer.u64(value);
    }
    encode_workload_decode_limits(writer, record.workload_decode);
    encode_evaluation_plan(writer, record.evaluation_plan);
    encode_replay_problem(writer, record.replay_problem);
    encode_replay_budgets(writer, record.replay_budgets);
    writer.digest(record.replay_plan_digest);
    writer.u64(record.capacity.max_live_disk_bytes);
    writer.u64(record.capacity.max_resident_ram_bytes);
    writer.u64(record.capacity.min_free_disk_bytes);
    writer.u64(record.host_budget.observed_available_disk_bytes);
    writer.u64(record.host_budget.observed_physical_ram_bytes);
    writer.u64(record.host_budget.max_live_disk_bytes);
    writer.u64(record.host_budget.max_resident_ram_bytes);
    writer.u64(record.client_private_persistent_bytes);
    writer.u64s(record.multiplication_scratch_bytes_by_reduction);
    writer.u64(record.request_wire_bytes);
    writer.u64(record.response_wire_bytes);
    writer.u64(record.ciphertext_wire_bytes);
    writer.u64(record.request_max_ciphertexts);
    writer.u64(record.response_max_ciphertexts);
    writer.u64(record.proof_max_ciphertexts);
    writer.u64(record.proof_max_collection_elements);
    writer.u64(record.proof_max_field_elements);
    writer.u64(record.proof_max_digests);
    writer.u64(record.gate_mle_retained_prover_key_bytes);
    writer.u64(record.gate_mle_opening_workspace_bytes);
    writer.u64(record.gate_mle_retained_prover_key_disk_bytes);
    writer.u64(record.gate_mle_opening_workspace_disk_bytes);
    writer.u64(record.gate_mle_affine_preparation_workspace_bytes);
    writer.u64(record.server_common_resident_bytes);
    writer.u64(record.server_payload_gkr_only_resident_bytes);
    writer.u64(record.server_packing_only_resident_bytes);
    writer.u64(record.reduction_workspace_resident_bytes);
    writer.u64(record.client_peak_resident_bytes);
    writer.digest(record.packing_preflight_digest);
    writer.u64(record.packing_persistent_overlap_bytes);
    writer.u64(record.packing_peak_live_bytes);
    return std::move(writer).finish();
}

std::vector<std::uint8_t> encode_setup(const ProcessSetupRecord &record) {
    std::vector<std::uint8_t> body = encode_setup_body(record);
    const Digest checksum = sha256(body);
    body.insert(body.end(), checksum.begin(), checksum.end());
    return body;
}

ProcessSetupRecord decode_setup(std::span<const std::uint8_t> encoded) {
    if (encoded.size() <= Digest{}.size() ||
        encoded.size() > kMaximumSetupRecordBytes) {
        throw std::invalid_argument("setup record size is invalid");
    }
    const auto body = encoded.first(encoded.size() - Digest{}.size());
    Digest checksum{};
    std::copy(encoded.end() - static_cast<std::ptrdiff_t>(checksum.size()),
              encoded.end(), checksum.begin());
    if (sha256(body) != checksum) {
        throw std::invalid_argument("setup record checksum mismatch");
    }
    Reader reader(body);
    const auto setup_domain = reader.text("setup domain");
    const auto codec_version = reader.u64("setup version");
    if (setup_domain != kSetupDomain ||
        codec_version != kSetupVersion) {
        throw std::invalid_argument("setup record header is invalid");
    }
    ProcessSetupRecord result;
    result.codec_version = codec_version;
    result.variant = reader.text("variant");
    result.profile = reader.text("profile");
    result.git_commit = reader.text("git commit");
    result.build_type = reader.text("build type");
    result.seal_acceleration = reader.text("SEAL acceleration");
    result.run_id = reader.digest("run id");
    result.root_storage_identity = reader.digest("root storage identity");
    result.workload_semantic_identity = reader.digest("workload identity");
    result.public_setup_digest = reader.digest("public setup digest");
    result.circuit_digest = reader.digest("circuit digest");
    result.fhe_context_storage_id = reader.digest("FHE context id");
    result.proof_ingress_policy = reader.text("proof ingress policy");
    result.proof_ingress_schedule_digest =
        reader.digest("proof ingress schedule digest");
    result.slots = reader.u64("slots");
    result.lanes = reader.u64("lanes");
    result.multiplicative_depth = reader.u64("depth");
    result.middle_width = reader.u64("width");
    result.payload_operations = reader.u64("payload operations");
    result.input_ciphertexts = reader.u64("input ciphertexts");
    result.output_ciphertexts = reader.u64("output ciphertexts");
    result.packing_repetitions = reader.u64("packing repetitions");
    result.selected_packing_repetitions =
        reader.u64("selected packing repetitions");
    result.basefold_queries = reader.u64("BaseFold queries");
    result.selected_basefold_queries =
        reader.u64("selected BaseFold queries");
    result.basefold_log_rate = reader.u64("BaseFold log rate");
    result.ciphertext_commitment_policy_code =
        reader.u64("ciphertext commitment policy");
    {
        const std::vector<std::size_t> widths =
            reader.sizes("data prime widths", 64);
        result.data_prime_bit_sizes.reserve(widths.size());
        for (const std::size_t width : widths) {
            if (width > static_cast<std::size_t>(
                            std::numeric_limits<int>::max())) {
                throw std::invalid_argument(
                    "data prime width exceeds int");
            }
            result.data_prime_bit_sizes.push_back(
                static_cast<int>(width));
        }
    }
    result.special_prime_bits = reader.u64("special prime bits");
    result.data_primes = reader.u64s("data primes", 64);
    result.special_prime = reader.u64("special prime");
    result.fresh_modulus_product_bits =
        reader.u64("fresh modulus product bits");
    result.key_modulus_product_bits =
        reader.u64("key modulus product bits");
    result.diagnostic_stress_only = reader.boolean("diagnostic flag");
    result.evaluation_bundle = decode_bundle(reader, "evaluation bundle");
    result.client_bundle = decode_bundle(reader, "client bundle");
    result.verifier_bundle = decode_bundle(reader, "verifier bundle");
    result.fixed_message_basis = decode_bundle(reader, "fixed basis");
    result.fixed_message_basis_artifact_id =
        reader.digest("fixed basis artifact id");
    result.fixed_message_basis_ntt_bytes =
        reader.u64("fixed basis NTT bytes");
    result.workload_max_bytes = reader.u64("workload max bytes");
    result.role_static_max_bytes = reader.u64("role-static max bytes");
    result.manifest_max_bytes = reader.u64("manifest max bytes");
    result.artifact_tree_files = reader.u64("tree files");
    result.artifact_tree_directories = reader.u64("tree directories");
    result.artifact_tree_file_max_bytes = reader.u64("tree file max bytes");
    result.artifact_tree_total_bytes = reader.u64("tree total bytes");
    result.factored_tensor_count = reader.u64("tensor count");
    result.workload_decode = decode_workload_decode_limits(reader);
    result.evaluation_plan = decode_evaluation_plan(reader);
    result.replay_problem = decode_replay_problem(reader);
    result.replay_budgets = decode_replay_budgets(reader);
    result.replay_plan_digest = reader.digest("replay plan digest");
    result.capacity.max_live_disk_bytes = reader.u64("disk cap");
    result.capacity.max_resident_ram_bytes = reader.u64("RAM cap");
    result.capacity.min_free_disk_bytes = reader.u64("free-space floor");
    result.host_budget.observed_available_disk_bytes =
        reader.u64("host observed available disk");
    result.host_budget.observed_physical_ram_bytes =
        reader.u64("host observed physical RAM");
    result.host_budget.max_live_disk_bytes =
        reader.u64("host live-disk budget");
    result.host_budget.max_resident_ram_bytes =
        reader.u64("host resident budget");
    result.client_private_persistent_bytes =
        reader.u64("client-private persistent bytes");
    result.multiplication_scratch_bytes_by_reduction =
        reader.u64s("GKR scratch caps");
    result.request_wire_bytes = reader.u64("request wire cap");
    result.response_wire_bytes = reader.u64("response wire cap");
    result.ciphertext_wire_bytes = reader.u64("ciphertext wire cap");
    result.request_max_ciphertexts =
        reader.u64("request ciphertext cap");
    result.response_max_ciphertexts =
        reader.u64("response ciphertext cap");
    result.proof_max_ciphertexts = reader.u64("proof ciphertext cap");
    result.proof_max_collection_elements =
        reader.u64("proof collection cap");
    result.proof_max_field_elements = reader.u64("proof field cap");
    result.proof_max_digests = reader.u64("proof digest cap");
    result.gate_mle_retained_prover_key_bytes =
        reader.u64("GateMLE retained prover-key reserve");
    result.gate_mle_opening_workspace_bytes =
        reader.u64("GateMLE opening workspace reserve");
    result.gate_mle_retained_prover_key_disk_bytes =
        reader.u64("GateMLE retained prover-key disk reserve");
    result.gate_mle_opening_workspace_disk_bytes =
        reader.u64("GateMLE opening workspace disk reserve");
    result.gate_mle_affine_preparation_workspace_bytes =
        reader.u64("affine GateMLE preparation workspace reserve");
    result.server_common_resident_bytes =
        reader.u64("server common resident reserve");
    result.server_payload_gkr_only_resident_bytes =
        reader.u64("server payload/GKR resident reserve");
    result.server_packing_only_resident_bytes =
        reader.u64("server packing resident reserve");
    result.reduction_workspace_resident_bytes =
        reader.u64("reduction workspace resident reserve");
    result.client_peak_resident_bytes =
        reader.u64("client peak resident reserve");
    result.packing_preflight_digest =
        reader.digest("packing preflight digest");
    result.packing_persistent_overlap_bytes =
        reader.u64("packing persistent overlap");
    result.packing_peak_live_bytes = reader.u64("packing peak");
    reader.require_end();
    if (encode_setup(result) !=
        std::vector<std::uint8_t>(encoded.begin(), encoded.end())) {
        throw std::invalid_argument("setup record is not canonical");
    }
    return result;
}

void encode_artifact_peak(Writer &writer,
                          const PayloadLayerArtifactPeak &peak) {
    writer.u64(peak.input_layer);
    writer.u64(peak.output_layer);
    writer.u64(peak.live_checkpoint_bytes);
    writer.u64(peak.input_artifact_bytes);
    writer.boolean(peak.input_counted_in_live_checkpoint_bytes);
    writer.u64(peak.additional_transient_input_bytes);
    writer.u64(peak.output_artifact_bytes);
    writer.u64(peak.proof_ingress_artifact_bytes_upper_bound);
    writer.boolean(peak.transient_input_retired_after_output_publish);
    writer.boolean(peak.output_retired_after_next_layer_or_gkr);
    writer.u64(peak.peak_live_scratch_bytes);
}

void encode_storage_profile(Writer &writer,
                            const PayloadCheckpointStorageProfile &profile) {
    writer.sizes(profile.checkpoint_layers);
    writer.u64(profile.checkpoint_metadata_bytes);
    writer.u64(profile.checkpoint_metadata_validation_buffer_bytes);
    writer.u64(profile.checkpoint_bytes);
    writer.u64(profile.chunk_ciphertexts);
    writer.u64(
        profile.dense_multiplication_alias_cache_peak_resident_bytes);
    writer.u64(profile.retained_output_peak_resident_bytes);
    encode_artifact_peak(writer, profile.forward_artifact_peak);
    writer.u64(profile.forward_peak_live_scratch_bytes);
    writer.u64(profile.proof_ingress_artifact_bytes_upper_bound);
    writer.u64(profile.proof_ingress_peak_live_scratch_bytes);
    writer.u64(profile.proof_ingress_peak_resident_bytes);
    writer.u64(
        profile.post_replay_consumer_artifact_bytes_upper_bound);
    writer.u64(
        profile.post_replay_consumer_peak_live_scratch_bytes);
    writer.u64(profile.peak_live_scratch_bytes);
    writer.u64(profile.peak_resident_bytes);
    writer.u64(profile.initial_forward_work_units);
    writer.u64(profile.replay_work_units);
    writer.u64(profile.cumulative_work_units);
    writer.boolean(profile.live_scratch_feasible);
    writer.boolean(profile.resident_feasible);
    writer.boolean(profile.recomputation_feasible);
}

Digest replay_plan_digest(const PayloadCheckpointReplayPlan &plan) {
    Writer writer;
    writer.text("LaminateImpl/PackedCheckpointReplayPlan/v3");
    encode_storage_profile(writer, plan.full_trace_reference);
    encode_storage_profile(writer, plan.selected);
    writer.u64(plan.reverse_gkr_segments.size());
    for (const PayloadReplaySegment &segment : plan.reverse_gkr_segments) {
        writer.u64(segment.reduction_layer);
        writer.u64(segment.required_source_layer);
        writer.u64(segment.checkpoint_layer);
        writer.u64(segment.replay_output_layer_begin);
        writer.u64(segment.replay_output_layer_end);
        writer.u64(segment.replay_work_units);
        writer.u64(segment.proof_ingress_artifact_bytes_upper_bound);
        writer.u64(segment.proof_ingress_peak_live_scratch_bytes);
        writer.u64(segment.proof_ingress_peak_resident_bytes);
        writer.u64(segment.post_replay_consumer_artifact_bytes);
        writer.u64(
            segment.post_replay_consumer_peak_live_scratch_bytes);
        encode_artifact_peak(writer, segment.artifact_peak);
        writer.u64(segment.serialized_peak_input_layer);
        writer.u64(segment.serialized_peak_output_layer);
        writer.u64(segment.serialized_input_chunk_bytes);
        writer.u64(segment.serialized_output_chunk_bytes);
        writer.u64(segment.resident_peak_input_layer);
        writer.u64(segment.resident_peak_output_layer);
        writer.u64(segment.resident_input_chunk_bytes);
        writer.u64(segment.resident_output_chunk_bytes);
        writer.u64(segment.peak_resident_bytes);
        writer.u64(segment.checkpoint_bytes_retired_after);
        writer.u64(segment.fixed_metadata_bytes_retired_after);
        writer.u64(segment.live_checkpoint_bytes_after);
    }
    writer.boolean(plan.used_nonpreferred_checkpoint);
    return sha256(writer.view());
}

Digest packing_preflight_digest(
    const TranscriptPackingExternalPreflightReport &report) {
    Writer writer;
    writer.text("LaminateImpl/PackedCheckpointPackingPreflight/v1");
    writer.u64(report.prefix_storage.outer_assignment_physical_bytes);
    writer.u64(
        report.prefix_storage.outer_assignment_peak_working_field_bytes);
    writer.u64(report.prefix_storage
                   .outer_assignment_construction_peak_live_storage_bytes);
    const auto &spartan = report.spartan_storage;
    for (const std::uint64_t value : {
             spartan.admitted_live_storage_bytes,
             spartan.outer_assignment_physical_bytes,
             spartan.factored_tensor_columns_physical_bytes,
             spartan.factored_tensor_columns_validation_bytes,
             spartan.factored_external_states_physical_bytes,
             spartan.factored_external_states_validation_bytes,
             spartan.preprocessing_validation_bytes,
             spartan.persistent_input_physical_bytes,
             spartan.assignment_physical_bytes,
             spartan.matrix_products_physical_bytes,
             spartan.witness_state_physical_bytes,
             spartan.wiring_matrix_physical_bytes,
             spartan.assignment_construction_peak_live_storage_bytes,
             spartan.witness_commitment_peak_live_storage_bytes,
             spartan.matrix_product_construction_peak_live_storage_bytes,
             spartan.pre_fiat_shamir_live_storage_bytes,
             spartan.constraint_check_peak_live_storage_bytes,
             spartan.wiring_construction_peak_live_storage_bytes,
             spartan.wiring_check_peak_live_storage_bytes,
             spartan.factored_evaluation_peak_live_storage_bytes,
             spartan.witness_opening_peak_live_storage_bytes,
             spartan.peak_live_storage_bytes,
         }) {
        writer.u64(value);
    }
    return sha256(writer.view());
}

std::uint64_t packing_peak_live_bytes(
    const TranscriptPackingExternalPreflightReport &report) {
    return std::max(
        report.prefix_storage
            .outer_assignment_construction_peak_live_storage_bytes,
        report.spartan_storage.peak_live_storage_bytes);
}

Digest random_digest() {
    std::array<std::uint8_t, 64> entropy{};
    std::random_device random;
    for (std::uint8_t &byte : entropy) {
        byte = static_cast<std::uint8_t>(random());
    }
    return sha256(entropy);
}

std::int64_t unix_milliseconds() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string json_string(std::string_view value) {
    std::string result{"\""};
    for (const char character : value) {
        if (character == '\"' || character == '\\') {
            result.push_back('\\');
        }
        result.push_back(character);
    }
    result.push_back('\"');
    return result;
}

class RoleActivity {
  public:
    RoleActivity(std::filesystem::path path, std::string_view role)
        : path_(std::move(path)), role_(role),
          uncaught_on_entry_(std::uncaught_exceptions()) {
        descriptor_ = ::open(path_.c_str(),
                             O_WRONLY | O_APPEND | O_CREAT | O_EXCL |
                                 O_CLOEXEC,
                             S_IRUSR | S_IWUSR);
        if (descriptor_ < 0) {
            throw std::runtime_error(
                "role activity already exists or cannot be created: " +
                path_.string());
        }
        if (::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            const int saved = errno;
            ::close(descriptor_);
            descriptor_ = -1;
            ::unlink(path_.c_str());
            throw std::system_error(saved, std::generic_category(),
                                    "failed to lock role activity");
        }
        append("start", "starting");
    }

    RoleActivity(const RoleActivity &) = delete;
    RoleActivity &operator=(const RoleActivity &) = delete;

    ~RoleActivity() {
        if (descriptor_ < 0) {
            return;
        }
        if (!complete_) {
            append_best_effort(
                "stop", std::uncaught_exceptions() > uncaught_on_entry_
                            ? "exception"
                            : "stopped_without_result");
        }
        (void)::flock(descriptor_, LOCK_UN);
        (void)::close(descriptor_);
    }

    void transition(std::string_view stage) noexcept {
        stage_ = std::string(stage);
        append_best_effort("stage", stage_);
    }

    void heartbeat() noexcept { append_best_effort("heartbeat", stage_); }

    void mark_complete() noexcept {
        if (complete_) {
            return;
        }
        complete_ = true;
        stage_ = "complete";
        append_best_effort("stop", stage_);
    }

  private:
    std::string line(std::string_view event, std::string_view stage) const {
        std::ostringstream output;
        output << "{\"schema\":\"laminate-role-activity-v1\",\"role\":"
               << json_string(role_) << ",\"event\":" << json_string(event)
               << ",\"stage\":" << json_string(stage) << ",\"pid\":"
               << static_cast<std::uint64_t>(::getpid())
               << ",\"unix_ms\":" << unix_milliseconds() << "}\n";
        return output.str();
    }

    void append(std::string_view event, std::string_view stage) {
        const std::string value = line(event, stage);
        std::size_t offset = 0;
        while (offset != value.size()) {
            const ssize_t count = ::write(descriptor_, value.data() + offset,
                                          value.size() - offset);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::system_error(
                    count < 0 ? errno : EIO, std::generic_category(),
                    "failed to append role activity");
            }
            offset += static_cast<std::size_t>(count);
        }
        (void)::fsync(descriptor_);
    }

    void append_best_effort(std::string_view event,
                            std::string_view stage) noexcept {
        try {
            append(event, stage);
        } catch (...) {
        }
    }

    std::filesystem::path path_;
    std::string role_;
    std::string stage_ = "starting";
    int descriptor_ = -1;
    int uncaught_on_entry_ = 0;
    bool complete_ = false;
};

void publish_private_file(const std::filesystem::path &path,
                          std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        throw std::invalid_argument("cannot publish an empty artifact");
    }
    CompletedResultReport report(path);
    std::ostream *output = report.mirror();
    output->write(reinterpret_cast<const char *>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    if (!*output) {
        throw std::runtime_error("failed to stage binary artifact");
    }
    report.publish();
}

const char *packed_output_noise_target_result(
    const PackedOutputNoiseAudit &audit, bool target_enforced) {
    if (!target_enforced) {
        return "NOT-ENFORCED-DIAGNOSTIC";
    }
    return packed_output_noise_target_passes(audit) ? "PASS" : "FAIL";
}

void emit_packed_output_noise_audit(
    const Record &output, const PackedOutputNoiseAudit &audit,
    bool target_enforced) {
    output.text(
        "noise.final_output.measurement",
        "client-secret-exact-canonical-error-with-invariant-budget-"
        "secondary-diagnostic");
    output.integer("noise.final_output.encrypted_ciphertext_count",
                   audit.encrypted_ciphertext_count);
    output.integer("noise.final_output.data_rns_limb_count",
                   audit.data_rns_limb_count);
    output.integer("noise.final_output.data_modulus_product_bits",
                   audit.data_modulus_product_bits);
    output.integer("noise.final_output.minimum_invariant_noise_budget_bits",
                   audit.minimum_invariant_noise_budget_bits);
    output.integer(
        "noise.final_output.maximum_invariant_budget_implied_phase_norm_bits",
        audit.maximum_invariant_budget_implied_phase_norm_bits);
    output.integer("noise.final_output.maximum_canonical_error_norm",
                   audit.maximum_canonical_error_norm);
    output.integer("noise.final_output.maximum_canonical_error_norm_bits",
                   audit.maximum_canonical_error_norm_bits);
    output.integer("noise.final_output.target_maximum_norm_bits",
                   kPackedOutputMaximumCanonicalErrorNormBits);
    output.text("noise.final_output.target_enforced",
                target_enforced ? "yes" : "no");
    output.text("noise.final_output.target_result",
                packed_output_noise_target_result(audit,
                                                  target_enforced));
    output.text(
        "noise.final_output.claim",
        "secret-key-assisted-exact-canonical-error-honest-run-diagnostic-"
        "not-certificate");
}

void publish_client_proof_verification_checkpoint(
    const ProcessCommand &command, std::int64_t finished_unix_ms) {
    CompletedResultReport report(
        command.run_directory / "client" /
        "proof-verification-result.txt");
    const Record output(report.mirror());
    output.text("format",
                "laminate-packed-client-proof-verification-v1");
    output.text("run.variant", command.variant_name);
    output.text("run.profile", command.profile_name);
    output.integer("timing.client.verification_finished_unix_ms",
                   finished_unix_ms);
    output.text("verification.result", "PASS");
    report.publish();
}

void publish_client_output_noise_checkpoint(
    const ProcessCommand &command, const PackedOutputNoiseAudit &audit,
    bool target_enforced) {
    CompletedResultReport report(
        command.run_directory / "client" / "output-noise-result.txt");
    const Record output(report.mirror());
    output.text("format", "laminate-packed-output-noise-audit-v1");
    output.text("run.variant", command.variant_name);
    output.text("run.profile", command.profile_name);
    emit_packed_output_noise_audit(output, audit, target_enforced);
    report.publish();
}

void publish_run_binding(const ProcessCommand &command,
                         const Digest &run_id) {
    CompletedResultReport report(command.run_directory / "shared" /
                                 "run-binding.txt");
    *report.mirror()
        << "format=laminate-benchmark-run-v1\n"
        << "run.variant=" << command.variant_name << '\n'
        << "run.profile=" << command.profile_name << '\n'
        << "run.id=" << digest_hex(run_id) << '\n';
    report.publish();
}

std::vector<std::uint8_t> read_bounded_file(
    const std::filesystem::path &path, std::uint64_t maximum_bytes) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("required artifact is missing: " +
                                 path.string());
    }
    const std::uint64_t bytes = std::filesystem::file_size(path, error);
    if (error || bytes == 0 || bytes > maximum_bytes) {
        throw std::runtime_error("artifact has invalid size: " +
                                 path.string());
    }
    std::ifstream input(path, std::ios::binary);
    std::vector<std::uint8_t> result(checked_size(bytes, "artifact size"));
    input.read(reinterpret_cast<char *>(result.data()),
               static_cast<std::streamsize>(result.size()));
    if (!input || input.peek() != std::ifstream::traits_type::eof()) {
        throw std::runtime_error("failed to read exact artifact: " +
                                 path.string());
    }
    return result;
}

BundleBinding publish_bundle(const std::filesystem::path &path,
                             std::span<const std::uint8_t> bytes) {
    publish_private_file(path, bytes);
    return {bytes.size(), sha256(bytes)};
}

std::vector<std::uint8_t> load_bundle(const std::filesystem::path &path,
                                      const BundleBinding &binding) {
    std::vector<std::uint8_t> bytes =
        read_bounded_file(path, binding.bytes);
    if (bytes.size() != binding.bytes || sha256(bytes) != binding.digest) {
        throw std::runtime_error("preprocessing bundle binding mismatch: " +
                                 path.string());
    }
    return bytes;
}

bool regular_file_exists(const std::filesystem::path &path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    return !error && std::filesystem::is_regular_file(status);
}

bool result_contains(const std::filesystem::path &path,
                     std::string_view needle) {
    std::ifstream input(path);
    for (std::string line; std::getline(input, line);) {
        if (line == needle) {
            return true;
        }
    }
    return false;
}

struct ProcessCompletion {
    bool protocol_pass = false;
    bool exit_recorded = false;
    bool exit_zero = false;
    bool exit_timed_out = false;
    bool failed = false;
    bool accepted = false;
};

ProcessCompletion inspect_process_completion(
    bool protocol_pass, const std::filesystem::path &result_path,
    const std::filesystem::path &exit_path,
    const std::filesystem::path &failure_path) {
    ProcessCompletion result;
    result.protocol_pass = protocol_pass;
    result.exit_recorded = regular_file_exists(exit_path);
    result.exit_zero = result.exit_recorded &&
                       result_contains(exit_path,
                                       "process.exit_status=0");
    if (result.protocol_pass && !result.exit_recorded) {
        std::error_code error;
        const auto written =
            std::filesystem::last_write_time(result_path, error);
        result.exit_timed_out =
            error || std::filesystem::file_time_type::clock::now() - written >
                         std::chrono::seconds(10);
    }
    result.failed = regular_file_exists(failure_path) ||
                    (result.exit_recorded && !result.exit_zero) ||
                    result.exit_timed_out;
    result.accepted = result.protocol_pass && result.exit_recorded &&
                      result.exit_zero;
    return result;
}

std::string_view completion_label(const ProcessCompletion &completion) {
    if (completion.accepted) {
        return "PASS";
    }
    if (completion.failed) {
        return "FAILED";
    }
    return completion.protocol_pass ? "finishing (awaiting process exit)"
                                    : "not complete";
}

enum class RoleProcessState : std::uint8_t {
    Missing,
    Active,
    Inactive,
    Invalid,
};

struct RoleProcessSnapshot {
    RoleProcessState state = RoleProcessState::Missing;
    std::optional<std::string> last_line;
    std::string diagnostic;
};

std::optional<std::string> last_complete_line(
    const std::filesystem::path &path) {
    std::ifstream input(path);
    if (!input) {
        return std::nullopt;
    }
    std::optional<std::string> result;
    for (std::string line; std::getline(input, line);) {
        if (input.eof()) {
            break;
        }
        if (!line.empty()) {
            result = std::move(line);
        }
    }
    return result;
}

RoleProcessSnapshot inspect_role_process(
    const std::filesystem::path &path) {
    RoleProcessSnapshot result;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory ||
        (!error && status.type() ==
                       std::filesystem::file_type::not_found)) {
        return result;
    }
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        result.state = RoleProcessState::Invalid;
        result.diagnostic = "activity marker is not a safe regular file";
        return result;
    }
    int flags = O_RDWR | O_CLOEXEC;
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path.c_str(), flags);
    if (descriptor < 0) {
        result.state = RoleProcessState::Invalid;
        result.diagnostic = "activity marker cannot be opened";
        return result;
    }
    if (::flock(descriptor, LOCK_EX | LOCK_NB) == 0) {
        result.state = RoleProcessState::Inactive;
        (void)::flock(descriptor, LOCK_UN);
    } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
        result.state = RoleProcessState::Active;
    } else {
        result.state = RoleProcessState::Invalid;
        result.diagnostic = "activity lock cannot be inspected";
    }
    (void)::close(descriptor);
    result.last_line = last_complete_line(path);
    return result;
}

std::optional<std::string> published_failure(
    const std::filesystem::path &path) {
    if (!regular_file_exists(path)) {
        return std::nullopt;
    }
    const std::vector<std::uint8_t> bytes =
        read_bounded_file(path, 16U << 10U);
    return std::string(reinterpret_cast<const char *>(bytes.data()),
                       bytes.size());
}

Timing add_timings(std::initializer_list<Timing> values) {
    Timing result;
    for (const Timing &value : values) {
        result.wall_ms += value.wall_ms;
        result.cpu_ms += value.cpu_ms;
    }
    return result;
}

void emit_exact_timing(const Record &record, std::string_view prefix,
                       const Timing &timing) {
    record.real(std::string(prefix) + ".wall_ms", timing.wall_ms);
    record.real(std::string(prefix) + ".cpu_ms", timing.cpu_ms);
}

Timing wait_for_artifact(
    const std::filesystem::path &path, std::string_view role,
    std::string_view artifact_description, RoleActivity &activity,
    std::string_view stage, const std::filesystem::path &peer_failure,
    const std::filesystem::path &peer_activity) {
    Stopwatch timer;
    activity.transition(stage);
    auto next_notice = std::chrono::steady_clock::now() +
                       std::chrono::seconds(60);
    std::optional<std::chrono::steady_clock::time_point> inactive_since;
    while (true) {
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        if (!error && std::filesystem::is_regular_file(status)) {
            return timer.stop();
        }
        if (error && error != std::errc::no_such_file_or_directory) {
            throw std::runtime_error("cannot inspect expected artifact: " +
                                     path.string());
        }
        if (!error && status.type() !=
                          std::filesystem::file_type::not_found) {
            throw std::runtime_error(
                "expected artifact path is not a regular file: " +
                path.string());
        }
        if (const auto failure = published_failure(peer_failure)) {
            throw std::runtime_error(
                "peer failed while waiting for " +
                std::string(artifact_description) + ": " + *failure);
        }
        const auto now = std::chrono::steady_clock::now();
        const RoleProcessSnapshot peer = inspect_role_process(peer_activity);
        if (peer.state == RoleProcessState::Invalid) {
            throw std::runtime_error(
                "cannot safely inspect peer activity while waiting for " +
                std::string(artifact_description) + ": " +
                peer.diagnostic);
        }
        if (peer.state == RoleProcessState::Inactive) {
            if (!inactive_since) {
                inactive_since = now;
            } else if (now - *inactive_since >= std::chrono::seconds(3)) {
                throw std::runtime_error(
                    "peer is no longer running and did not publish " +
                    std::string(artifact_description));
            }
        } else {
            inactive_since.reset();
        }
        activity.heartbeat();
        if (now >= next_notice) {
            const auto seconds = static_cast<std::uint64_t>(
                timer.stop().wall_ms / 1000.0);
            std::cerr << role << ": idle; waiting for "
                      << artifact_description << " (elapsed "
                      << std::setfill('0') << std::setw(2) << seconds / 3600U
                      << ':' << std::setw(2) << (seconds / 60U) % 60U << ':'
                      << std::setw(2) << seconds % 60U << std::setfill(' ')
                      << ")\n";
            next_notice = now + std::chrono::seconds(60);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void publish_failure(const ProcessCommand &command,
                     std::string_view message) noexcept {
    try {
        std::filesystem::path path;
        std::filesystem::path activity_path;
        std::filesystem::path completed_path;
        std::string_view completed_line;
        if (command.action == ProcessAction::Setup) {
            path = command.run_directory / "shared" / "setup-failure.txt";
            activity_path = command.run_directory / "shared" /
                            "setup-activity.jsonl";
            completed_path = command.run_directory / "shared" /
                             "setup-result.txt";
            completed_line = "setup.result=PASS";
        } else if (command.action == ProcessAction::RunClient) {
            path = command.run_directory / "client" / "failure.txt";
            activity_path = command.run_directory / "client" /
                            "activity.jsonl";
            completed_path = command.run_directory / "client" /
                             "result.txt";
            completed_line = "verification.result=PASS";
        } else if (command.action == ProcessAction::RunServer) {
            path = command.run_directory / "server" / "failure.txt";
            activity_path = command.run_directory / "server" /
                            "activity.jsonl";
            completed_path = command.run_directory / "server" /
                             "result.txt";
            completed_line = "server.result=PASS";
        } else {
            return;
        }
        if (!std::filesystem::is_directory(path.parent_path()) ||
            result_contains(completed_path, completed_line) ||
            inspect_role_process(activity_path).state ==
                RoleProcessState::Active ||
            regular_file_exists(path)) {
            return;
        }
        const std::string contents =
            "FAILED: " + clean(std::string(message)) + '\n';
        publish_private_file(
            path,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(contents.data()),
                contents.size()));
    } catch (...) {
    }
}

WorkloadSpec workload_spec(const PackedProcessProfile &profile) {
    return benchmark_payload_workload_spec(
        benchmark_payload_profile(profile.tier),
        profile.variant == PackedProcessVariant::Folded
            ? PayloadShape::wide(profile.slots)
            : PayloadShape::laned(profile.lanes, profile.slots));
}

PackingGkrVariant packing_variant(PackedProcessVariant variant) {
    return variant == PackedProcessVariant::Folded
               ? PackingGkrVariant::Folded
               : PackingGkrVariant::Laned;
}

SealParameters seal_parameters(const PackedProcessProfile &profile) {
    return SealParameters{
        .poly_modulus_degree = profile.slots,
        .fresh_rns_limbs = profile.data_prime_bit_sizes.size(),
        .data_prime_bit_sizes = profile.exact_data_primes.empty()
                                   ? profile.data_prime_bit_sizes
                                   : std::vector<int>{},
        .exact_data_primes = profile.exact_data_primes,
        .exact_special_prime = profile.exact_special_prime,
        .special_prime_bits = profile.special_prime_bits,
        .security_level = seal::sec_level_type::none,
        .track_deterministic_noise_bounds = false,
        .max_fresh_ciphertext_modulus_bits =
            packed_process_uses_folded_pyramid_headroom(profile)
                ? kFoldedPyramidDataModulusBits
                : profile.fresh_modulus_width_sum_bits(),
        .max_key_modulus_bits = packed_process_uses_folded_pyramid_headroom(profile)
                ? kFoldedPyramidKeyModulusBits
                : profile.key_modulus_width_sum_bits(),
        // Fixed-message alignment performs setup-fixed grid rotations.
        .generate_galois_keys = true,
    };
}

TranscriptPackingExternalPreprocessingSpecification
packing_specification(const PackedProcessProfile &profile,
                      const LayeredCircuit &circuit) {
    LazyTernaryParameters parameters =
        selected_lazy_ternary_parameters();
    parameters.repetitions = profile.packing_repetitions;
    const PackingGkrVariant variant = packing_variant(profile.variant);
    return {
        .variant = variant,
        .ciphertext_commitment_policy =
            profile.ciphertext_commitment_policy,
        .ring_degree = profile.slots,
        .bhip_round_count =
            variant == PackingGkrVariant::Folded
                ? folded_bhip_round_count(circuit)
                : laned_bhip_round_count(circuit),
        .parameters = parameters,
        .basefold_parameters = {
            .log_rate = profile.basefold_log_rate,
            .query_count = profile.basefold_queries,
        },
        .staging_block_elements = kIoBlockElements,
        .canonical_copy_block_elements = kIoBlockElements,
        .basefold_block_elements = kBaseFoldTransformTileElements,
        .proof_ingress_policy = packed_process_proof_ingress_policy(profile),
    };
}

TranscriptPackingExternalPreprocessingLimits external_setup_limits(
    const TranscriptPackingExternalPreprocessingPlan &plan,
    std::uint64_t min_free_bytes) {
    TranscriptPackingExternalPreprocessingLimits result{
        .staging_artifact = {
            .max_total_bytes = plan.staging.artifact_physical_bytes,
            .min_free_bytes = min_free_bytes,
        },
        .max_staging_working_bytes = plan.staging.peak_working_bytes,
        .canonical_tensor_artifact = {
            .max_total_bytes =
                plan.factored.canonical_artifact_physical_bytes,
            .min_free_bytes = min_free_bytes,
        },
        .max_live_physical_bytes =
            plan.factored.conservative_peak_live_physical_bytes,
        .max_copy_working_field_bytes =
            plan.factored.peak_copy_working_field_bytes,
    };
    for (const auto &tensor : plan.factored.tensors) {
        result.tensors.push_back({
            .max_final_physical_bytes =
                tensor.commitment.final_physical_bytes,
            .max_scratch_physical_bytes =
                tensor.commitment.scratch_peak_physical_bytes,
            .min_free_bytes = min_free_bytes,
            .max_working_field_bytes =
                tensor.commitment.peak_working_field_bytes,
        });
    }
    return result;
}

PackedRolePreprocessingPublishLimits role_publication_limits(
    const CertifiedPackedWorkloadStatic &workload,
    const PackedRolePreprocessingPublicationPlan &plan,
    std::uint64_t min_free_bytes) {
    const std::uint64_t role_static = std::max(
        plan.server_role_static_bytes, plan.client_role_static_bytes);
    return {
        .storage = {
            .max_workload_bytes =
                plan.workload_decode_requirements.max_artifact_bytes,
            .max_role_artifact_bytes = role_static,
            .max_manifest_bytes = kPackedRoleManifestMaxBytes,
            .min_free_bytes = min_free_bytes,
            .max_artifact_tree_files = plan.server_artifacts.file_count,
            .max_artifact_tree_directories =
                plan.server_artifacts.directory_count,
            .max_artifact_tree_depth = 2,
            .max_artifact_tree_relative_path_bytes = 256,
            .max_artifact_tree_file_bytes =
                plan.server_artifacts.serialized_bytes,
            .max_artifact_tree_bytes =
                plan.server_artifacts.serialized_bytes,
            .workload_decode = plan.workload_decode_requirements,
        },
        .role_static = {
            .max_encoded_bytes = checked_size(role_static, "role-static"),
            .max_ingress_layers = workload.circuit().layers.size(),
            .max_factored_tensors =
                plan.transcript_packing.factored.tensors.size(),
            .max_relative_path_bytes = 64,
        },
        .transcript_packing =
            external_setup_limits(plan.transcript_packing, min_free_bytes),
    };
}

PackedSetupPrepublicationDemand packed_setup_prepublication_demand(
    const BundleBinding &evaluation, const BundleBinding &client,
    const BundleBinding &verifier, const BundleBinding &fixed_basis,
    std::uint64_t workload_bytes,
    const PackedRolePreprocessingPublicationPlan &plan,
    const PackedRolePreprocessingPublishLimits &limits,
    const GateMleProverResourceBounds &gate_resources,
    std::uint64_t persisted_gate_mle_bytes) {
    require(persisted_gate_mle_bytes <=
                gate_resources.retained_prover_key_disk_bytes,
            "persisted GateMLE cache exceeds its admitted disk bound");
    require(plan.client_artifacts.serialized_bytes == 0 &&
                plan.server_artifacts.serialized_bytes ==
                    plan.transcript_packing.factored
                        .persistent_output_physical_bytes,
            "packed setup artifact plan has unexpected ownership");
    const std::uint64_t artifact_bytes = checked_add(
        plan.server_artifacts.serialized_bytes,
        plan.client_artifacts.serialized_bytes,
        "packed setup persistent artifact bytes");
    require(plan.transcript_packing.factored
                    .conservative_peak_live_physical_bytes >=
                artifact_bytes,
            "packed setup construction peak omits persistent artifacts");

    const std::uint64_t fhe_persistent = checked_add(
        checked_add(evaluation.bytes, client.bytes,
                    "packed setup FHE bundle bytes"),
        checked_add(verifier.bytes, fixed_basis.bytes,
                    "packed setup FHE bundle bytes"),
        "packed setup FHE bundle bytes");
    const std::uint64_t role_static_bytes = checked_add(
        plan.server_role_static_bytes, plan.client_role_static_bytes,
        "packed setup role-static bytes");
    // The three authenticated manifests are not known byte-for-byte until
    // their tree digests exist. Charge each public cap, plus the setup-record
    // cap and a small lifecycle/result envelope, before any large write.
    const std::uint64_t metadata_bytes = checked_add(
        checked_multiply(kPackedPublicationManifestCount,
                         limits.storage.max_manifest_bytes,
                         "packed setup manifest reserve"),
        checked_add(kMaximumSetupRecordBytes, kOnlineMetadataDiskReserve,
                    "packed setup metadata reserve"),
        "packed setup metadata reserve");
    const std::uint64_t final_persistent = checked_add(
        checked_add(
            checked_add(fhe_persistent, workload_bytes,
                        "packed setup persistent bytes"),
            role_static_bytes, "packed setup persistent bytes"),
        checked_add(checked_add(artifact_bytes, metadata_bytes,
                    "packed setup persistent bytes"),
                    gate_resources.retained_prover_key_disk_bytes,
                    "packed persisted GateMLE index disk"),
        "packed setup persistent bytes");
    const std::uint64_t transient_artifact_bytes =
        plan.transcript_packing.factored
            .conservative_peak_live_physical_bytes -
        artifact_bytes;
    const std::uint64_t peak_live = checked_add(
        final_persistent, transient_artifact_bytes,
        "packed setup construction live bytes");

    // This is the reserve for work after the admission boundary; the
    // process-lifetime high-water already observed before this point is
    // charged separately. Independent FHE reopening is sequential, but SEAL
    // loading and canonical validation may transiently retain the wire image,
    // a decoded key/context, and a reserialized image. Charge all three even
    // though the role bundles are not reopened concurrently. Role
    // authentication is likewise sequential, so at most the original and one
    // reopened decoded workload coexist with the canonical encoding. Charge
    // each decoded representation four times its wire size for
    // container/object overhead. The external planner supplies the remaining
    // controlled workspace.
    const std::uint64_t workload_resident = checked_add(
        checked_multiply(
            2 * kDecodedWorkloadResidentMultiplier, workload_bytes,
            "packed setup decoded-workload resident reserve"),
        workload_bytes, "packed setup workload resident reserve");
    const std::uint64_t remaining_setup_resident_reserve = checked_add(
        checked_add(
            checked_multiply(3, fhe_persistent,
                             "packed setup FHE resident reserve"),
            workload_resident,
            "packed setup resident reserve"),
        checked_add(
            checked_add(role_static_bytes,
                        plan.transcript_packing.peak_working_bytes,
                        "packed setup external resident reserve"),
            kResidentSafetySlack, "packed setup resident slack"),
        "packed setup peak resident bytes");
    return {
        .already_present_persistent_bytes = checked_add(fhe_persistent,
            persisted_gate_mle_bytes, "already persisted GateMLE cache"),
        .final_persistent_bytes = final_persistent,
        .peak_live_bytes = peak_live,
        .remaining_setup_resident_reserve_bytes =
            remaining_setup_resident_reserve,
    };
}

PackedRolePreprocessingOpenLimits role_open_limits(
    const ProcessSetupRecord &record,
    const PackedProcessProfile &profile) {
    return {
        .storage = {
            .max_workload_bytes = record.workload_max_bytes,
            .max_role_artifact_bytes = record.role_static_max_bytes,
            .max_manifest_bytes = record.manifest_max_bytes,
            .max_artifact_tree_files = record.artifact_tree_files,
            .max_artifact_tree_directories =
                record.artifact_tree_directories,
            .max_artifact_tree_depth = 2,
            .max_artifact_tree_relative_path_bytes = 256,
            .max_artifact_tree_file_bytes =
                record.artifact_tree_file_max_bytes,
            .max_artifact_tree_bytes = record.artifact_tree_total_bytes,
            .workload_decode = record.workload_decode,
        },
        .role_static = {
            .max_encoded_bytes = checked_size(
                record.role_static_max_bytes, "role-static"),
            .max_ingress_layers = 2 * profile.multiplicative_depth + 8,
            .max_factored_tensors = checked_size(
                record.factored_tensor_count, "tensor count"),
            .max_relative_path_bytes = 64,
        },
    };
}

FheEvaluationPlan evaluation_plan(
    const PackedProcessProfile &profile,
    const LayeredCircuit &circuit,
    const ConservativePackedProofIngressSchedule &ingress) {
    std::vector<std::size_t> proof_depths;
    proof_depths.reserve(ingress.rns_limbs_by_layer().size());
    for (const std::size_t limbs : ingress.rns_limbs_by_layer()) {
        if (limbs == 0) {
            throw std::logic_error("fixed packed ingress selected zero limbs");
        }
        proof_depths.push_back(limbs - 1U);
    }
    if (!proof_depths.empty()) {
        proof_depths.front() = 0;
    }
    return packed_process_evaluation_plan(profile, circuit, proof_depths);
}

PayloadCheckpointReplayProblem replay_problem(
    const CertifiedCanonicalTraceLayout &trace,
    const FheEvaluationPlan &evaluation,
    std::size_t fresh_rns_limbs) {
    std::vector<std::uint64_t> serialized;
    std::vector<std::uint64_t> resident;
    serialized.reserve(fresh_rns_limbs);
    resident.reserve(fresh_rns_limbs);
    for (std::size_t limbs = 1; limbs <= fresh_rns_limbs; ++limbs) {
        const std::uint64_t raw = checked_multiply(
            checked_multiply(2, trace.circuit().shape.slot_count,
                             "ciphertext coefficients"),
            checked_multiply(limbs, sizeof(std::uint64_t),
                             "ciphertext limbs"),
            "ciphertext bytes");
        serialized.push_back(checked_add(raw, 64U << 10U,
                                         "serialized ciphertext bound"));
        resident.push_back(checked_add(raw, 128U << 10U,
                                       "resident ciphertext bound"));
    }
    return make_packed_checkpoint_replay_problem(
        trace, evaluation,
        PackedCheckpointReplayResourceBounds{
            .serialized_ciphertext_bytes_by_rns_limb =
                std::move(serialized),
            .resident_ciphertext_bytes_by_rns_limb = std::move(resident),
            .checkpoint_set_fixed_bytes = 159,
            .checkpoint_set_bytes_per_layer = 8,
        });
}

struct MultiplicationWorkspaceBounds {
    std::uint64_t builder = 0;
    std::uint64_t reduction = 0;
};

std::vector<std::uint64_t> multiplication_scratch_caps(
    const LayeredCircuit &circuit, const CanonicalTraceLayout &trace,
    const PayloadCheckpointReplayProblem &problem,
    std::uint64_t process_disk_cap,
    MultiplicationWorkspaceBounds *workspace = nullptr) {
    std::vector<std::uint64_t> result(circuit.layers.size() - 1U, 0);
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (layer_kind(circuit.layers[layer]) !=
            LayerKind::Multiplication) {
            continue;
        }
        const auto aliases =
            gkr::detail::make_dense_multiplication_alias_plan(
                circuit, layer, trace.wire_support.at(layer + 1U),
                trace.storage.at(layer + 1U));
        const PayloadReplayLayer &source = problem.layers.at(layer + 1U);
        const std::uint64_t record_bytes =
            source.proof_ingress_serialized_ciphertext_bytes == 0
                ? source.serialized_ciphertext_bytes
                : source.proof_ingress_serialized_ciphertext_bytes;
        const auto bounds =
            gkr::detail::file_dense_multiplication_source_disk_bounds(
                aliases.operands.size(), record_bytes,
                true);
        require(bounds.build_peak_bytes != 0 &&
                    bounds.completed_artifact_bytes != 0 &&
                    bounds.build_peak_bytes <= process_disk_cap,
                "derived multiplication scratch exceeds process disk cap");
        result[layer] = bounds.build_peak_bytes;
        if (workspace) {
            const auto resident = std::max({source.resident_ciphertext_bytes,
                source.proof_ingress_resident_ciphertext_bytes,
                checked_add(std::max(source.serialized_ciphertext_bytes,
                                     source.proof_ingress_serialized_ciphertext_bytes),
                            1, "tagged multiplication record")});
            workspace->builder = std::max(workspace->builder,
                gkr::detail::dense_multiplication_builder_workspace_bytes(
                    aliases, resident, source.stored_value_count));
            workspace->reduction = std::max(workspace->reduction,
                gkr::detail::dense_multiplication_reduction_workspace_bytes(
                    aliases, resident, problem.layers[layer].virtual_wire_count));
        }
    }
    return result;
}

struct ProcessRamPolicy {
    std::uint64_t server_common_bytes = 0;
    std::uint64_t server_payload_gkr_only_bytes = 0;
    std::uint64_t server_packing_only_bytes = 0;
    std::uint64_t reduction_workspace_bytes = 0;
    std::uint64_t client_peak_bytes = 0;
};

constexpr std::uint64_t kPayloadStorageTransferResidentBytes =
    3U * kFileTraceStoreTransferBufferBytes;

std::uint64_t process_laned_affine_reduction_workspace_bytes(
    const ProcessSetupRecord &record) {
    if (record.variant != "laned") {
        return 0;
    }
    require(record.lanes != 0 && record.slots % record.lanes == 0,
            "Laned affine RAM accounting has invalid lane geometry");
    return bench::laned_affine_reduction_workspace_bytes(
        checked_size(record.slots, "Laned slots"),
        checked_size(record.lanes, "Laned lanes"),
        record.replay_problem);
}

// Upper-bound alias metadata directly from the persisted replay geometry.
// This admits every legal alias pattern without materializing another copy
// of the source plan at every budget check.
MultiplicationWorkspaceBounds multiplication_workspace_bounds(
    const ProcessSetupRecord &record) {
    require(record.variant != "laned" ||
                (record.lanes != 0 && record.slots % record.lanes == 0),
            "multiplication workspace has invalid lane geometry");
    const std::size_t chunks = record.variant == "laned"
        ? checked_size(record.slots / record.lanes, "packed source chunks") : 1;
    require(chunks != 0, "multiplication source chunks must be nonzero");
    MultiplicationWorkspaceBounds result;
    for (std::size_t layer = 0; layer + 1U < record.replay_problem.layers.size(); ++layer) {
        if (record.replay_problem.layers[layer].kind != LayerKind::Multiplication)
            continue;
        const auto &source = record.replay_problem.layers[layer + 1U];
        const auto pairs = std::max<std::size_t>(
            1, source.virtual_wire_count / (2U * chunks));
        const auto operands = checked_multiply(2, pairs, "packed operand count");
        const auto signatures = checked_multiply(operands, chunks, "packed signature entries");
        const auto resident = std::max({source.resident_ciphertext_bytes,
            source.proof_ingress_resident_ciphertext_bytes,
            checked_add(std::max(source.serialized_ciphertext_bytes,
                                 source.proof_ingress_serialized_ciphertext_bytes),
                        1, "tagged multiplication record")});
        result.builder = std::max(result.builder,
            gkr::detail::dense_multiplication_builder_ram_bound(
                pairs, operands, signatures, source.stored_value_count, resident));
        const auto metadata = gkr::detail::dense_multiplication_metadata_ram_bound(
            pairs, operands, signatures, source.stored_value_count);
        const auto reduction = checked_add(
            checked_add(metadata,
                gkr::detail::dense_multiplication_alias_reader_ram_bound(resident),
                "packed multiplication alias reader"),
            checked_add(checked_multiply(gkr::detail::kDenseMultiplicationReaderCacheValues + 4U,
                                 resident, "packed multiplication reader"),
                checked_multiply(record.replay_problem.layers[layer].virtual_wire_count,
                                 sizeof(Fpk), "packed multiplication output weights"),
                "packed multiplication reduction"),
            "packed multiplication reduction");
        result.reduction = std::max(result.reduction, reduction);
    }
    return result;
}

/// Conservative resident envelopes derived from the exact setup artifacts
/// and wire caps.  The server common reserve charges the restored SEAL
/// context, fixed NTT basis, decoded workload/role certificate, retained
/// typed response proof, and process slack.  Payload/GKR additionally charges
/// both raw and decoded request representations and any eager Laned mask
/// cache and builder. Packing additionally
/// charges one response-sized encoding destination and the largest configured
/// external field workspace.  The client peak analogously covers restored
/// client/verifier state and the larger of request encoding or response
/// decode-and-verify.
ProcessRamPolicy process_ram_policy(const ProcessSetupRecord &record) {
    const std::uint64_t server_context = checked_add(
        checked_multiply(2, record.evaluation_bundle.bytes,
                         "restored evaluation context reserve"),
        record.fixed_message_basis_ntt_bytes,
        "server FHE preprocessing reserve");
    const std::uint64_t server_static = checked_add(
        record.workload_max_bytes, record.role_static_max_bytes,
        "server decoded static-state reserve");
    const std::uint64_t server_common = checked_add(
        checked_add(
            checked_add(server_context, server_static,
                        "server common static reserve"),
            record.gate_mle_retained_prover_key_bytes,
            "server common GateMLE reserve"),
        checked_add(record.response_wire_bytes, kResidentSafetySlack,
                    "retained proof and server slack"),
        "server common resident reserve");
    const std::uint64_t eager_laned_workspace = record.variant == "laned"
        ? eager_laned_witness_packing_resources(
              checked_size(record.slots, "Laned slots"),
              checked_size(record.lanes, "Laned lanes"),
              record.replay_problem).resident_workspace_bytes
        : 0;
    const std::uint64_t request_workspace = checked_add(
        checked_multiply(2, record.request_wire_bytes,
                         "raw and decoded request reserve"),
        checked_add(kCodecWorkingSlack,
                    kPayloadStorageTransferResidentBytes,
                    "payload codec and storage-transfer reserve"),
        "payload codec workspace reserve");
    const std::uint64_t payload_only = checked_add(
        request_workspace, eager_laned_workspace,
        "payload and eager Laned workspace reserve");
    const std::uint64_t packing_only = checked_add(
        record.response_wire_bytes, kExternalPackingWorkingPeak,
        "packing encoding and external workspace reserve");
    const std::uint64_t reduction_workspace = std::max({
        kExternalPackingWorkingPeak,
        multiplication_workspace_bounds(record).reduction,
        checked_add(record.gate_mle_opening_workspace_bytes,
                    record.gate_mle_affine_preparation_workspace_bytes,
                    "gate opening and program construction"),
        process_laned_affine_reduction_workspace_bytes(record),
        checked_multiply(
            4,
            checked_multiply(kReplayChunkCiphertexts,
                             record.ciphertext_wire_bytes,
                             "reduction ciphertext chunk reserve"),
            "reduction reader/writer/accumulator reserve")});

    const std::uint64_t client_static = checked_add(
        checked_add(
            checked_multiply(2, record.client_bundle.bytes,
                             "restored client context reserve"),
            checked_multiply(2, record.verifier_bundle.bytes,
                             "restored verifier context reserve"),
            "client FHE context reserve"),
        checked_add(record.workload_max_bytes, record.role_static_max_bytes,
                    "client decoded static-state reserve"),
        "client static resident reserve");
    const std::uint64_t client_request_peak = checked_multiply(
        2, record.request_wire_bytes, "client request codec reserve");
    const std::uint64_t client_response_peak = checked_multiply(
        2, record.response_wire_bytes,
        "client raw and decoded response reserve");
    const std::uint64_t client_peak = checked_add(
        checked_add(client_static,
                    std::max(client_request_peak, client_response_peak),
                    "client static and codec reserve"),
        kResidentSafetySlack, "client resident safety slack");
    return {
        .server_common_bytes = server_common,
        .server_payload_gkr_only_bytes = payload_only,
        .server_packing_only_bytes = packing_only,
        .reduction_workspace_bytes = reduction_workspace,
        .client_peak_bytes = client_peak,
    };
}

/// Give the multiplication-source reorder the RAM that is genuinely free in
/// its phase.  The host budget has already removed the OS reserve and the
/// concurrent client peak.  The remaining subtraction preserves all server
/// state and the ordinary reduction workspace.  This is a capacity limit:
/// small layers allocate only their encoded records, not the whole limit.
std::uint64_t process_multiplication_sort_buffer_bytes(
    const ProcessSetupRecord &record) {
    const ProcessRamPolicy ram = process_ram_policy(record);
    const std::uint64_t fixed = checked_add(
        checked_add(ram.server_common_bytes,
                    ram.server_payload_gkr_only_bytes,
                    "multiplication builder fixed RAM"),
        checked_add(ram.reduction_workspace_bytes,
                    multiplication_workspace_bounds(record).builder,
                    "multiplication builder workspace reserve"),
        "multiplication builder fixed RAM");
    require(record.capacity.max_resident_ram_bytes >= fixed,
            "multiplication builder fixed RAM exceeds the server cap");
    const std::uint64_t available =
        (record.capacity.max_resident_ram_bytes - fixed) / 2U;
    require(available >=
                gkr::detail::kDenseMultiplicationSortMaxBufferedPayloadBytes,
            "host RAM leaves less than 4 GiB for multiplication-source "
            "ordering");
    return available;
}

PayloadCheckpointReplayBudgets replay_budgets(
    const ProcessCapacity &capacity, std::uint64_t reserved_server_bytes,
    const ProcessSetupRecord &record) {
    const ProcessRamPolicy ram = process_ram_policy(record);
    return {
        .max_live_scratch_bytes = capacity.max_live_disk_bytes,
        .max_resident_ciphertext_bytes = capacity.max_resident_ram_bytes,
        .max_ciphertexts_per_chunk = kReplayChunkCiphertexts,
        .max_recomputation_factor = kMaximumRecomputation,
        .reserved_live_scratch_bytes = reserved_server_bytes,
        .reserved_resident_bytes = checked_add(
            ram.server_common_bytes,
            ram.server_payload_gkr_only_bytes,
            "payload/GKR resident reserve"),
        .selection_objective =
            PayloadCheckpointSelectionObjective::MinimumReplayWork,
        .post_replay_consumer_artifact_bytes_by_reduction =
            record.multiplication_scratch_bytes_by_reduction,
    };
}

SealFixedMessageCellPreprocessingDecodeLimits fixed_basis_limits(
    const ProcessSetupRecord &record) {
    return {
        .max_artifact_bytes = checked_size(
            record.fixed_message_basis.bytes, "fixed basis bytes"),
        .max_ntt_coefficient_bytes = checked_size(
            record.fixed_message_basis_ntt_bytes, "fixed basis NTT bytes"),
    };
}

void require_build_for_setup() {
    if (std::string_view(LAMINATE_PACKED_CHECKPOINT_GIT_DIRTY) != "false" ||
        std::string_view(LAMINATE_BUILD_TYPE) != "Release" ||
        std::string_view(LAMINATE_SEAL_ACCELERATION) !=
            "intel-hexl-runtime-dispatch") {
        throw std::runtime_error(
            "packed GCP setup requires a clean Release Intel-HEXL build");
    }
    if (!fq_ntt_backend_available(FqNttBackend::IntelHexl)) {
        throw std::runtime_error(
            "packed GCP setup requires the Intel-HEXL native-Fq NTT adapter");
    }
    const auto features = cpu_features();
    if (!features.avx2_available || !features.avx512f_available ||
        !features.avx512dq_available || !features.avx512ifma_available) {
        throw std::runtime_error(
            "packed GCP setup requires AVX2 and AVX-512 F/DQ/IFMA");
    }
}

void require_record_binding(const ProcessCommand &command,
                            const PackedProcessProfile &profile,
                            const ProcessSetupRecord &record,
                            bool require_current_git_commit = true) {
    const std::uint64_t minimum_client_private_bytes = checked_add(
        record.client_bundle.bytes, record.verifier_bundle.bytes,
        "minimum client-private persistence");
    if (record.variant != command.variant_name ||
        record.profile != command.profile_name ||
        (require_current_git_commit &&
         record.git_commit != LAMINATE_PACKED_CHECKPOINT_GIT_COMMIT) ||
        record.build_type != LAMINATE_BUILD_TYPE ||
        record.seal_acceleration != LAMINATE_SEAL_ACCELERATION ||
        record.proof_ingress_policy !=
            conservative_packed_proof_ingress_policy(
                packing_variant(profile.variant),
                packed_process_proof_ingress_policy(profile)) ||
        record.proof_ingress_schedule_digest == Digest{} ||
        record.evaluation_plan.proof_ingress_mult_depth_by_layer.empty() ||
        record.slots != profile.slots || record.lanes != profile.lanes ||
        record.multiplicative_depth != profile.multiplicative_depth ||
        record.middle_width != profile.middle_width ||
        record.payload_operations != profile.payload_operations ||
        record.input_ciphertexts != profile.input_ciphertexts ||
        record.output_ciphertexts != profile.output_ciphertexts ||
        record.packing_repetitions != profile.packing_repetitions ||
        record.selected_packing_repetitions !=
            profile.selected_packing_repetitions ||
        record.basefold_queries != profile.basefold_queries ||
        record.selected_basefold_queries != profile.selected_basefold_queries ||
        record.basefold_log_rate != profile.basefold_log_rate ||
        gkr::CiphertextCommitmentPolicy::from_wire_code(
            record.ciphertext_commitment_policy_code) !=
            profile.ciphertext_commitment_policy ||
        record.data_prime_bit_sizes != profile.data_prime_bit_sizes ||
        (!profile.exact_data_primes.empty() &&
         (record.data_primes != profile.exact_data_primes ||
          record.special_prime != profile.exact_special_prime ||
          record.fresh_modulus_product_bits != kFoldedPyramidDataModulusBits ||
          record.key_modulus_product_bits != kFoldedPyramidKeyModulusBits)) ||
        record.special_prime_bits !=
            static_cast<std::uint64_t>(profile.special_prime_bits) ||
        record.data_primes.size() != profile.fresh_rns_limbs() ||
        record.data_primes.empty() ||
        record.data_primes.front() != kOuterFieldOrder ||
        record.special_prime == 0 ||
        record.fresh_modulus_product_bits == 0 ||
        record.key_modulus_product_bits == 0 ||
        record.diagnostic_stress_only !=
            profile.is_reduced_security_stress_test() ||
        record.workload_decode.max_artifact_bytes !=
            record.workload_max_bytes ||
        record.workload_decode.max_slots != profile.slots ||
        record.workload_decode.max_payload_plaintexts == 0 ||
        record.workload_decode.max_payload_gates !=
            record.payload_operations ||
        record.workload_decode.max_payload_outputs !=
            profile.output_ciphertexts ||
        record.workload_decode.max_layers == 0 ||
        record.workload_decode.max_layer_gates == 0 ||
        record.workload_decode.max_affine_terms == 0 ||
        record.workload_decode.max_storage_entries == 0 ||
        record.workload_decode.max_gate_tables == 0 ||
        record.gate_mle_retained_prover_key_bytes == 0 ||
        record.gate_mle_opening_workspace_bytes == 0 ||
        record.client_private_persistent_bytes <
            minimum_client_private_bytes ||
        record.client_private_persistent_bytes >
            conservative_adaptive_client_private_persistent_bytes(profile)) {
        throw std::runtime_error(
            "setup record does not match this executable/profile");
    }
    std::vector<std::size_t> committed_ingress_limbs;
    committed_ingress_limbs.reserve(
        record.evaluation_plan.proof_ingress_mult_depth_by_layer.size());
    for (const std::size_t depth :
         record.evaluation_plan.proof_ingress_mult_depth_by_layer) {
        if (depth == std::numeric_limits<std::size_t>::max()) {
            throw std::runtime_error(
                "setup record has an invalid proof-ingress depth");
        }
        committed_ingress_limbs.push_back(depth + 1U);
    }
    // The output is never a reverse-GKR source. The operational evaluation
    // plan preserves its natural payload level, while the committed ingress
    // schedule canonically binds a one-limb placeholder at index zero.
    committed_ingress_limbs.front() = 1U;
    require(
        record.proof_ingress_schedule_digest ==
            conservative_packed_proof_ingress_schedule_digest(
                packing_variant(profile.variant), record.circuit_digest,
                record.public_setup_digest, committed_ingress_limbs,
                packed_process_proof_ingress_policy(profile)),
        "setup record proof-ingress schedule digest is invalid");
    const ProcessRamPolicy ram = process_ram_policy(record);
    const ProcessCapacity capacity = process_capacity(
        record.host_budget, record.client_private_persistent_bytes,
        ram.client_peak_bytes);
    require(record.server_common_resident_bytes ==
                    ram.server_common_bytes &&
                record.server_payload_gkr_only_resident_bytes ==
                    ram.server_payload_gkr_only_bytes &&
                record.server_packing_only_resident_bytes ==
                    ram.server_packing_only_bytes &&
                record.reduction_workspace_resident_bytes ==
                    ram.reduction_workspace_bytes &&
                record.client_peak_resident_bytes == ram.client_peak_bytes &&
                record.client_private_persistent_bytes != 0 &&
                record.replay_budgets.reserved_resident_bytes ==
                    checked_add(ram.server_common_bytes,
                                ram.server_payload_gkr_only_bytes,
                                "bound payload/GKR resident reserve") &&
                record.capacity.max_live_disk_bytes ==
                    capacity.max_live_disk_bytes &&
                record.capacity.max_resident_ram_bytes ==
                    capacity.max_resident_ram_bytes &&
                record.capacity.min_free_disk_bytes ==
                    capacity.min_free_disk_bytes &&
                record.replay_budgets.max_live_scratch_bytes ==
                    capacity.max_live_disk_bytes &&
                record.replay_budgets.max_resident_ciphertext_bytes ==
                    capacity.max_resident_ram_bytes &&
                record.replay_budgets.max_ciphertexts_per_chunk ==
                    kReplayChunkCiphertexts &&
                record.replay_budgets.max_recomputation_factor ==
                    kMaximumRecomputation &&
                record.replay_budgets.selection_objective ==
                    PayloadCheckpointSelectionObjective::
                        MinimumReplayWork &&
                record.replay_budgets
                        .post_replay_consumer_artifact_bytes_by_reduction ==
                    record.multiplication_scratch_bytes_by_reduction &&
                record.multiplication_scratch_bytes_by_reduction.size() ==
                    record.replay_problem.layers.size() - 1U,
            "setup record resource policy is not canonical");
}

void require_run_binding(const ProcessCommand &command,
                         const ProcessSetupRecord &record) {
    const std::vector<std::uint8_t> bytes = read_bounded_file(
        command.run_directory / "shared" / "run-binding.txt", 1024);
    std::ostringstream expected;
    expected << "format=laminate-benchmark-run-v1\n"
             << "run.variant=" << command.variant_name << '\n'
             << "run.profile=" << command.profile_name << '\n'
             << "run.id=" << digest_hex(record.run_id) << '\n';
    const std::string expected_text = expected.str();
    require(bytes.size() == expected_text.size() &&
                std::equal(bytes.begin(), bytes.end(),
                           reinterpret_cast<const std::uint8_t *>(
                               expected_text.data())),
            "run binding does not match setup record");
}

ProcessSetupRecord load_setup_record(const ProcessCommand &command,
                                     const PackedProcessProfile &profile) {
    const std::vector<std::uint8_t> bytes = read_bounded_file(
        command.run_directory / "shared" / "setup.bin",
        kMaximumSetupRecordBytes);
    ProcessSetupRecord result = decode_setup(bytes);
    require_record_binding(command, profile, result);
    require_run_binding(command, result);
    return result;
}

class OneShotWorkTree {
  public:
    explicit OneShotWorkTree(std::filesystem::path root)
        : root_(std::move(root)) {
        std::error_code error;
        struct stat status {};
        if (::lstat(root_.c_str(), &status) != 0 ||
            !S_ISDIR(status.st_mode) ||
            !std::filesystem::is_empty(root_, error) || error) {
            throw std::invalid_argument(
                "one-shot work root must be an existing empty real directory");
        }
        device_ = status.st_dev;
        inode_ = status.st_ino;
    }

    OneShotWorkTree(const OneShotWorkTree &) = delete;
    OneShotWorkTree &operator=(const OneShotWorkTree &) = delete;

    ~OneShotWorkTree() {
        if (!root_identity_matches()) {
            return;
        }
        std::error_code ignored;
        for (auto entry = std::filesystem::directory_iterator(root_, ignored);
             !ignored && entry != std::filesystem::directory_iterator();) {
            const auto path = entry->path();
            entry.increment(ignored);
            struct stat status {};
            if (!root_identity_matches() ||
                ::lstat(path.c_str(), &status) != 0 ||
                !S_ISDIR(status.st_mode)) {
                return;
            }
            std::filesystem::remove_all(path, ignored);
            if (ignored) {
                return;
            }
        }
    }

    std::filesystem::path make(std::string_view name) {
        const std::filesystem::path result = root_ / name;
        make_private_directory(result);
        children_.push_back(result);
        return result;
    }

    bool empty_children() const {
        return root_identity_matches() && std::all_of(
            children_.begin(), children_.end(), [](const auto &path) {
                std::error_code error;
                struct stat status {};
                return ::lstat(path.c_str(), &status) == 0 &&
                       S_ISDIR(status.st_mode) &&
                       std::filesystem::is_empty(path, error) && !error;
            });
    }

    void require_empty() const {
        require(empty_children(),
                "one-shot work tree retained an artifact on success");
    }

    void retire_success() {
        require(root_identity_matches(),
                "one-shot work root identity changed");
        std::error_code error;
        for (auto entry = std::filesystem::recursive_directory_iterator(
                 root_, error);
             !error &&
             entry != std::filesystem::recursive_directory_iterator();
             entry.increment(error)) {
            const auto status = entry->symlink_status(error);
            require(!error && std::filesystem::is_directory(status) &&
                        !std::filesystem::is_symlink(status),
                    "successful one-shot work tree retained a file or link");
        }
        require(!error, "failed to inspect successful one-shot work tree");
        for (const auto &child : children_) {
            require(root_identity_matches(),
                    "one-shot work root identity changed during retirement");
            const std::uintmax_t removed =
                std::filesystem::remove_all(child, error);
            require(!error && removed != 0,
                    "failed to retire one-shot work directory");
        }
        require(std::filesystem::is_empty(root_, error) && !error,
                "one-shot work root is not empty after retirement");
        children_.clear();
    }

  private:
    bool root_identity_matches() const noexcept {
        struct stat status {};
        return ::lstat(root_.c_str(), &status) == 0 &&
               S_ISDIR(status.st_mode) && status.st_dev == device_ &&
               status.st_ino == inode_;
    }

    std::filesystem::path root_;
    std::vector<std::filesystem::path> children_;
    dev_t device_{};
    ino_t inode_{};
};

struct OnlineRoots {
    std::filesystem::path replay;
    std::vector<std::filesystem::path> gkr_multiplications;
    std::filesystem::path outer;
    std::filesystem::path assignment;
    std::filesystem::path products;
    std::filesystem::path witness_state;
    std::filesystem::path witness_commit_scratch;
    std::filesystem::path constraint_scratch;
    std::filesystem::path wiring_matrix;
    std::filesystem::path wiring_scratch;
    std::vector<std::filesystem::path> factored_opening_scratch;
    std::filesystem::path witness_opening_scratch;
};

OnlineRoots make_online_roots(OneShotWorkTree &tree,
                              const LayeredCircuit &circuit,
                              std::size_t tensor_count) {
    OnlineRoots result;
    result.replay = tree.make("payload-replay");
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == LayerKind::Multiplication) {
            result.gkr_multiplications.push_back(
                tree.make("gkr-multiplication-" + std::to_string(layer)));
        }
    }
    result.outer = tree.make("packing-outer");
    result.assignment = tree.make("spartan-assignment");
    result.products = tree.make("spartan-products");
    result.witness_state = tree.make("spartan-witness-state");
    result.witness_commit_scratch =
        tree.make("spartan-witness-commit-scratch");
    result.constraint_scratch = tree.make("spartan-constraint-scratch");
    result.wiring_matrix = tree.make("spartan-wiring-matrix");
    result.wiring_scratch = tree.make("spartan-wiring-scratch");
    for (std::size_t index = 0; index < tensor_count; ++index) {
        result.factored_opening_scratch.push_back(
            tree.make("spartan-factored-opening-" +
                      std::to_string(index)));
    }
    result.witness_opening_scratch =
        tree.make("spartan-witness-opening-scratch");
    return result;
}

TranscriptPackingExternalProverOptions packing_online_options(
    const OnlineRoots &roots, const ProcessSetupRecord &record) {
    // Every external primitive receives one of these explicit hard caps.
    // Setup preflight rejects a profile whose geometry requires more; the
    // process RAM policy can therefore charge their maximum exactly once.
    constexpr std::uint64_t kWorking = kExternalPackingBlockWorking;
    TranscriptPackingExternalProverOptions result{
        .outer_assignment = {
            .directory = roots.outer,
            .storage_limits = {
                .max_total_bytes = record.capacity.max_live_disk_bytes,
                .min_free_bytes = record.capacity.min_free_disk_bytes,
            },
            .max_working_field_bytes = kWorking,
            .block_elements = kIoBlockElements,
        },
        .spartan = {
            .max_live_storage_bytes = record.capacity.max_live_disk_bytes,
            .assignment = {
                .directory = roots.assignment,
                .storage_limits = {
                    .max_total_bytes = record.capacity.max_live_disk_bytes,
                    .min_free_bytes = record.capacity.min_free_disk_bytes,
                },
                .max_working_bytes = kWorking,
                .block_elements = kIoBlockElements,
            },
            .matrix_products = {
                .directory = roots.products,
                .storage_limits = {
                    .max_total_bytes = record.capacity.max_live_disk_bytes,
                    .min_free_bytes = record.capacity.min_free_disk_bytes,
                },
                .max_working_field_bytes = kWorking,
                .block_elements = kIoBlockElements,
            },
            .witness_commitment = {
                .destination_directory = roots.witness_state,
                .scratch_directory = roots.witness_commit_scratch,
                .max_final_bytes = record.capacity.max_live_disk_bytes,
                .max_scratch_bytes = record.capacity.max_live_disk_bytes,
                .min_free_bytes = record.capacity.min_free_disk_bytes,
                .max_working_field_bytes = kWorking,
                .block_elements = kBaseFoldTransformTileElements,
                .cache_radix_elements = 0,
            },
            .constraint_sumcheck = {
                .scratch_directory = roots.constraint_scratch,
                .max_live_storage_bytes = 1,
                .max_total_scratch_bytes =
                    record.capacity.max_live_disk_bytes,
                .min_free_bytes = record.capacity.min_free_disk_bytes,
                .max_working_field_bytes = kWorking,
                .block_elements = kIoBlockElements,
                .source_rounds = 4,
            },
            .wiring_matrix = {
                .directory = roots.wiring_matrix,
                .storage_limits = {
                    .max_total_bytes = record.capacity.max_live_disk_bytes,
                    .min_free_bytes = record.capacity.min_free_disk_bytes,
                },
                .max_live_storage_bytes = 1,
                .max_working_field_bytes = 2 * kWorking,
                .block_elements = kIoBlockElements,
            },
            .wiring_sumcheck = {
                .scratch_directory = roots.wiring_scratch,
                .max_live_storage_bytes = 1,
                .max_total_scratch_bytes =
                    record.capacity.max_live_disk_bytes,
                .min_free_bytes = record.capacity.min_free_disk_bytes,
                .max_working_field_bytes = kWorking,
                .block_elements = kIoBlockElements,
                .source_rounds = 4,
            },
            .factored_evaluation = {
                .tensor_openings = {},
                .max_live_storage_bytes = 1,
                .reserved_live_storage_bytes = 0,
                .max_working_field_bytes = 2 * kWorking,
            },
            .witness_opening = {
                .scratch_directory = roots.witness_opening_scratch,
                .max_live_storage_bytes = 1,
                .max_total_scratch_bytes =
                    record.capacity.max_live_disk_bytes,
                .min_free_bytes = record.capacity.min_free_disk_bytes,
                .max_working_field_bytes = kWorking,
                .fold_chunk_elements = 1U << 24U,
            },
        },
    };
    for (const auto &scratch : roots.factored_opening_scratch) {
        result.spartan.factored_evaluation.tensor_openings.push_back({
            .scratch_directory = scratch,
            .max_live_storage_bytes = 1,
            .max_total_scratch_bytes = record.capacity.max_live_disk_bytes,
            .min_free_bytes = record.capacity.min_free_disk_bytes,
            .max_working_field_bytes = kWorking,
            .fold_chunk_elements = 1U << 24U,
        });
    }
    return result;
}

FoldedServerProofOptions folded_gkr_options(
    const LayeredCircuit &circuit, const OnlineRoots &roots,
    const ProcessSetupRecord &record,
    RuntimeProgressCallback progress = {}) {
    FoldedServerProofOptions result;
    result.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
    result.reclaim_completed_multiplication_scratch = true;
    result.proof.progress = std::move(progress);
    std::size_t index = 0;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) != LayerKind::Multiplication) {
            continue;
        }
        result.proof.multiplication_scratch.push_back({
            .reduction_layer = layer,
            .directory = roots.gkr_multiplications.at(index++),
            .storage_limits = {
                .max_total_bytes =
                    record.multiplication_scratch_bytes_by_reduction.at(
                        layer),
                .min_free_bytes = record.capacity.min_free_disk_bytes,
            },
            .sort_buffer_payload_bytes =
                process_multiplication_sort_buffer_bytes(record),
        });
    }
    return result;
}

LanedServerProofOptions laned_gkr_options(
    const LayeredCircuit &circuit, const OnlineRoots &roots,
    const ProcessSetupRecord &record,
    RuntimeProgressCallback progress = {}) {
    LanedServerProofOptions result;
    result.lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry;
    result.reclaim_completed_multiplication_scratch = true;
    result.proof.progress = std::move(progress);
    std::size_t index = 0;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) != LayerKind::Multiplication) {
            continue;
        }
        result.proof.multiplication_scratch.push_back({
            .reduction_layer = layer,
            .directory = roots.gkr_multiplications.at(index++),
            .storage_limits = {
                .max_total_bytes =
                    record.multiplication_scratch_bytes_by_reduction.at(
                        layer),
                .min_free_bytes = record.capacity.min_free_disk_bytes,
            },
            .sort_buffer_payload_bytes =
                process_multiplication_sort_buffer_bytes(record),
        });
    }
    return result;
}

CheckpointReplayServerStorageLimits server_storage_limits(
    const LayeredCircuit &circuit, const ProcessSetupRecord &record) {
    const ProcessRamPolicy ram = process_ram_policy(record);
    require(ram.server_common_bytes ==
                    record.server_common_resident_bytes &&
                ram.server_payload_gkr_only_bytes ==
                    record.server_payload_gkr_only_resident_bytes &&
                ram.server_packing_only_bytes ==
                    record.server_packing_only_resident_bytes &&
                ram.reduction_workspace_bytes ==
                    record.reduction_workspace_resident_bytes &&
                ram.client_peak_bytes == record.client_peak_resident_bytes,
            "setup-derived resident-memory policy drifted");
    require(record.replay_budgets.reserved_live_scratch_bytes >=
                record.gate_mle_opening_workspace_disk_bytes,
            "replay reserve omits GateMLE opening disk");
    const std::uint64_t common_disk =
        record.replay_budgets.reserved_live_scratch_bytes -
        record.gate_mle_opening_workspace_disk_bytes;
    require(record.packing_peak_live_bytes >=
                record.packing_persistent_overlap_bytes,
            "packing live peak is below its persistent overlap");
    const std::uint64_t packing_only =
        record.packing_peak_live_bytes -
        record.packing_persistent_overlap_bytes;
    CheckpointReplayServerStorageLimits result{
        .caps = {
            .max_total_local_disk_bytes =
                record.capacity.max_live_disk_bytes,
            .max_resident_ram_bytes = record.capacity.max_resident_ram_bytes,
            .max_phase_combined_bytes = checked_add(
                record.capacity.max_live_disk_bytes,
                record.capacity.max_resident_ram_bytes,
                "combined server cap"),
        },
        .common = {common_disk, ram.server_common_bytes},
        .payload_gkr_only = {record.gate_mle_opening_workspace_disk_bytes,
                             ram.server_payload_gkr_only_bytes},
        .transcript_packing_only = {packing_only,
                                    ram.server_packing_only_bytes},
    };
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        const LayerKind kind = layer_kind(circuit.layers[layer]);
        result.reduction_workspaces.push_back({
            .reduction_layer = layer,
            .kind = kind,
            .multiplication_builder_phase_bytes =
                kind == LayerKind::Multiplication
                    ? checked_add(
                          checked_add(ram.reduction_workspace_bytes,
                              multiplication_workspace_bounds(record).builder,
                              "multiplication builder workspace reserve"),
                          checked_multiply(2, process_multiplication_sort_buffer_bytes(record),
                              "multiplication sort payload and metadata"),
                          "multiplication builder phase RAM")
                    : 0,
            .reduction_phase_bytes = ram.reduction_workspace_bytes,
        });
    }
    if (result.common.resident_ram_bytes +
            result.payload_gkr_only.resident_ram_bytes !=
        record.replay_budgets.reserved_resident_bytes) {
        throw std::logic_error("server reserve accounting drifted");
    }
    return result;
}

void require_host_capacity(
    const std::filesystem::path &filesystem_root,
    const ProcessCapacity &capacity,
    const CheckpointReplayServerStorageAdmission &admission,
    std::uint64_t persistent_server_bytes,
    std::uint64_t already_present_online_bytes = 0) {
    require(admission.max_local_disk_bytes <= capacity.max_live_disk_bytes,
            "server admission exceeds configured live-disk cap");
    require(admission.max_resident_ram_bytes <=
                capacity.max_resident_ram_bytes,
            "server admission exceeds configured RAM cap");
    const SystemInfo host = system_info();
    require(host.ram_bytes != 0 &&
                admission.max_resident_ram_bytes <= host.ram_bytes,
            "host RAM is below the admitted server peak");
    const std::uint64_t already_present = checked_add(
        persistent_server_bytes, already_present_online_bytes,
        "already-present server bytes");
    require(admission.max_local_disk_bytes >= already_present,
            "server admission omits already-present protocol files");
    const std::uint64_t additional_disk =
        admission.max_local_disk_bytes - already_present;
    std::error_code error;
    const std::filesystem::space_info space =
        std::filesystem::space(filesystem_root, error);
    require(!error && space.available >=
                          checked_add(additional_disk,
                                      capacity.min_free_disk_bytes,
                                      "host disk admission"),
            "host free disk is below the admitted server peak and reserve");
}

void require_concurrent_host_ram(
    const CheckpointReplayServerStorageAdmission &server,
    const ProcessSetupRecord &record) {
    require(record.client_peak_resident_bytes != 0,
            "setup-derived client resident peak is empty");
    require(record.client_peak_resident_bytes <=
                record.host_budget.max_resident_ram_bytes,
            "setup-derived client resident peak exceeds the gross "
            "host-derived resident envelope");
    const std::uint64_t concurrent_peak = checked_add(
        server.max_resident_ram_bytes, record.client_peak_resident_bytes,
        "concurrent server/client resident peak");
    const SystemInfo host = system_info();
    require(host.ram_bytes != 0 && concurrent_peak <= host.ram_bytes,
            "host RAM is below the admitted concurrent server/client peak");
    require(concurrent_peak <= record.host_budget.max_resident_ram_bytes,
            "admitted concurrent server/client peak consumes the fixed "
            "host RAM reserve");
}

void require_client_host_ram(const ProcessSetupRecord &record) {
    const ProcessRamPolicy ram = process_ram_policy(record);
    require(ram.client_peak_bytes == record.client_peak_resident_bytes,
            "setup-derived client resident-memory policy drifted");
    require(record.client_peak_resident_bytes != 0,
            "client resident peak is empty");
    require(record.client_peak_resident_bytes <=
                record.host_budget.max_resident_ram_bytes,
            "client resident peak exceeds the gross host-derived resident "
            "envelope");
    const SystemInfo host = system_info();
    require(host.ram_bytes != 0 &&
                record.client_peak_resident_bytes <= host.ram_bytes,
            "host RAM is below the admitted client peak");
}

void require_free_disk(const std::filesystem::path &root,
                       std::uint64_t additional_bytes,
                       std::uint64_t free_space_floor) {
    std::error_code error;
    const std::filesystem::space_info space =
        std::filesystem::space(root, error);
    require(!error &&
                space.available >=
                    checked_add(additional_bytes, free_space_floor,
                                "free-disk boundary"),
            "insufficient free disk at online publication boundary");
}

std::uint64_t regular_file_bytes(const std::filesystem::path &root) {
    std::uint64_t result = 0;
    std::error_code error;
    for (auto entry = std::filesystem::recursive_directory_iterator(root, error);
         !error && entry != std::filesystem::recursive_directory_iterator();
         entry.increment(error)) {
        if (entry->is_regular_file(error) && !error) {
            result = checked_add(
                result, entry->file_size(error), "preprocessing bytes");
        }
    }
    if (error) {
        throw std::runtime_error("failed to measure preprocessing tree: " +
                                 error.message());
    }
    return result;
}

std::uint64_t checkpoint_metadata_cap(
    const PayloadCheckpointReplayProblem &problem) {
    return std::max<std::uint64_t>(
        4096,
        checked_add(
            problem.checkpoint_set_fixed_bytes,
            checked_multiply(problem.checkpoint_set_bytes_per_layer,
                             problem.layers.size(),
                             "checkpoint metadata bytes"),
            "checkpoint metadata bytes"));
}

struct PreparedPackedServerRequestResources {
    std::optional<PreparedCheckpointReplayFoldedServerResources> folded;
    std::optional<PreparedCheckpointReplayLanedServerResources> laned;
    CheckpointReplayServerStorageAdmission storage_admission;
};

/// Construct the exact request-resource authority used by online evaluation.
/// Setup calls this on a disposable tree so deterministic root, variant,
/// replay, GKR, and storage mismatches cannot survive setup PASS.
PreparedPackedServerRequestResources
prepare_authenticated_packed_server_request_resources(
    const AuthenticatedPackedServerOnlineState<SealBackend> &server,
    const PackedProcessProfile &profile, const OnlineRoots &roots,
    const ProcessSetupRecord &record,
    TranscriptPackingExternalAdmission packing_admission,
    RuntimeProgressCallback progress = {}) {
    PayloadCheckpointReplayExecutionOptions replay_options{
        .directory = roots.replay,
        .min_free_bytes = record.capacity.min_free_disk_bytes,
        .max_checkpoint_metadata_bytes =
            checkpoint_metadata_cap(record.replay_problem),
        .lifecycle = FileTraceSessionLifecycle::IrreversibleNoRetry,
        .eager_laned_witness_packing =
            profile.variant == PackedProcessVariant::Laned &&
            supports_eager_laned_witness_packing(
                server.checkpoint_replay().circuit()),
        .progress = progress,
    };
    const CheckpointReplayServerStorageLimits storage_limits =
        server_storage_limits(server.checkpoint_replay().circuit(), record);
    PreparedPackedServerRequestResources result;
    if (profile.variant == PackedProcessVariant::Folded) {
        result.folded.emplace(
            prepare_folded_request_resources(
                server, std::move(replay_options),
                folded_gkr_options(server.checkpoint_replay().circuit(),
                                   roots, record, std::move(progress)),
                std::move(packing_admission), storage_limits));
        result.storage_admission = result.folded->storage_admission();
    } else {
        result.laned.emplace(
            prepare_laned_request_resources(
                server, std::move(replay_options),
                laned_gkr_options(server.checkpoint_replay().circuit(),
                                  roots, record, std::move(progress)),
                std::move(packing_admission), storage_limits));
        result.storage_admission = result.laned->storage_admission();
    }
    return result;
}

using PackedServerRestorePhase = std::function<void(std::string_view)>;

struct PackedServerStaticRestore {
    AuthenticatedPackedServerOnlineState<SealBackend> server;
    Timing load_preprocessing;
    Timing certify_replay_and_gkr_static;
};

/// Restore and certify the complete reusable server authority from one final
/// setup record. Setup and the fresh online process deliberately share this
/// routine; neither is allowed to stop at the weaker opened-role boundary.
PackedServerStaticRestore restore_and_certify_packed_server_static(
    const ProcessCommand &command, const PackedProcessProfile &profile,
    const ProcessSetupRecord &record,
    const PackedServerRestorePhase &phase = {},
    std::size_t setup_worker_threads = 1) {
    Stopwatch load_stopwatch;
    if (phase) {
        phase("restoring_evaluation_context");
    }
    SealBackend::EvalContext evaluation_context =
        SealBackend::deserialize_evaluation_context_bundle(load_bundle(
            command.run_directory / "server" / "preprocessing" /
                "evaluation-context.bin",
            record.evaluation_bundle));
    require(SealBackend::storage_context_id(evaluation_context) ==
                record.fhe_context_storage_id,
            "server evaluation-context identity mismatch");
    const std::vector<std::uint64_t> restored_moduli =
        SealBackend::coefficient_moduli(evaluation_context);
    require(restored_moduli.size() == record.data_primes.size() + 1U &&
                std::equal(record.data_primes.begin(),
                           record.data_primes.end(),
                           restored_moduli.begin()) &&
                restored_moduli.back() == record.special_prime &&
                SealBackend::key_modulus_bits(evaluation_context) ==
                    record.key_modulus_product_bits,
            "server SEAL coefficient-modulus binding mismatch");

    if (phase) {
        phase("restoring_fixed_message_basis");
    }
    {
        const std::vector<std::uint8_t> fixed_basis = load_bundle(
            command.run_directory / "server" / "preprocessing" /
                "fixed-message-basis.bin",
            record.fixed_message_basis);
        const SealFixedMessageCellPreprocessingMetadata fixed_metadata =
            SealBackend::restore_fixed_message_cell_preprocessing(
                evaluation_context, fixed_basis,
                record.fixed_message_basis_artifact_id,
                fixed_basis_limits(record));
        require(fixed_metadata.ntt_coefficient_bytes ==
                    record.fixed_message_basis_ntt_bytes,
                "fixed-message preprocessing metadata drifted");
    }

    if (phase) {
        phase("opening_packed_server_role");
    }
    auto opened = open_packed_server_evaluation<SealBackend>(
        command.run_directory / "shared" / "preprocessing" /
            "packed-shared",
        command.run_directory / "server" / "preprocessing" /
            "packed-server",
        record.root_storage_identity, std::move(evaluation_context),
        role_open_limits(record, profile), {},
        gates::GateTableBuildOptions{
            .wide_scratch_parent = command.run_directory / "server" / "gate-mle-scratch",
            .wide_max_disk_bytes = record.capacity.max_live_disk_bytes,
            .wide_resources = {.min_free_bytes = record.capacity.min_free_disk_bytes},
            .preprocessing_threads = setup_worker_threads,
            .prover_key_directory = command.run_directory / "server" / "preprocessing" / "gate-mle"});
    const CertifiedPackedWorkloadStatic &workload =
        opened.role().workload();
    require(opened.role().core().role_static.variant ==
                    packing_variant(profile.variant) &&
                workload.semantic_identity() ==
                    record.workload_semantic_identity &&
                workload.setup_digest() == record.public_setup_digest &&
                workload.circuit_digest() == record.circuit_digest &&
                workload.payload().gates.size() ==
                    record.payload_operations &&
                packed_workload_static_decode_requirements(
                    workload,
                    checked_size(record.workload_max_bytes,
                                 "workload bytes")) ==
                    record.workload_decode,
            "server preprocessing identity mismatch");
    const auto gate_resources = gate_mle_prover_resource_bounds(
        *workload.public_setup().outsourced_gate_mle);
    require(record.gate_mle_retained_prover_key_bytes == gate_resources.retained_prover_key_bytes &&
            record.gate_mle_opening_workspace_bytes == gate_resources.opening_workspace_bytes &&
            record.gate_mle_retained_prover_key_disk_bytes == gate_resources.retained_prover_key_disk_bytes &&
            record.gate_mle_opening_workspace_disk_bytes == gate_resources.opening_workspace_disk_bytes &&
            record.gate_mle_affine_preparation_workspace_bytes ==
                affine_gate_preparation_workspace_bytes(workload.circuit()),
            "GateMLE resource reserve differs from authenticated setup");
    record.evaluation_plan.validate(workload.circuit());
    const Timing load_timing = load_stopwatch.stop();

    if (phase) {
        phase("certifying_replay_and_gkr_static");
    }
    Stopwatch certify_stopwatch;
    const PayloadCheckpointReplayPlan replay =
        plan_payload_checkpoint_replay(record.replay_problem,
                                       record.replay_budgets);
    require(replay_plan_digest(replay) == record.replay_plan_digest,
            "server replay plan does not match setup");
    auto server = make_authenticated_packed_server_online_state<SealBackend>(
        std::move(opened), record.evaluation_plan,
        record.replay_problem, record.replay_budgets, replay);
    const Timing certify_timing = certify_stopwatch.stop();
    return {
        .server = std::move(server),
        .load_preprocessing = load_timing,
        .certify_replay_and_gkr_static = certify_timing,
    };
}

std::uint64_t packed_server_persistent_bytes(
    const ProcessCommand &command, const ProcessSetupRecord &record) {
    const std::uint64_t gate_mle_bytes = regular_file_bytes(
        command.run_directory / "server" / "preprocessing" / "gate-mle");
    require(gate_mle_bytes <= record.gate_mle_retained_prover_key_disk_bytes,
            "persisted GateMLE cache exceeds its admitted disk bound");
    return checked_add(
        checked_add(
            regular_file_bytes(command.run_directory / "shared" /
                               "preprocessing" / "packed-shared"),
            regular_file_bytes(command.run_directory / "server" /
                               "preprocessing" / "packed-server"),
            "persistent packed server bytes"),
        checked_add(
            checked_add(record.evaluation_bundle.bytes,
                        record.fixed_message_basis.bytes,
                        "persistent FHE server bytes"),
            gate_mle_bytes, "persistent FHE and GateMLE server bytes"),
        "persistent server bytes");
}

std::uint64_t packed_server_reserved_bytes(
    const ProcessSetupRecord &record,
    std::uint64_t persistent_server_bytes) {
    // The complete measured persistence already includes the GateMLE cache.
    // Refine its pre-setup upper bound to actual bytes and reserve only the
    // additional opening workspace here.
    return checked_add(
        checked_add(persistent_server_bytes,
            record.gate_mle_opening_workspace_disk_bytes,
            "persistent server and GateMLE disk reserve"),
        checked_add(
            checked_add(record.request_wire_bytes,
                        record.response_wire_bytes,
                        "online wire reserve"),
            kOnlineMetadataDiskReserve, "online metadata reserve"),
        "reserved server bytes");
}

void require_packed_server_reserve_binding(
    const ProcessSetupRecord &record,
    std::uint64_t persistent_server_bytes) {
    require(packed_server_reserved_bytes(record, persistent_server_bytes) ==
                record.replay_budgets.reserved_live_scratch_bytes,
            "server persistent/wire reserve drifted");
}

std::optional<std::uint64_t> pinned_logical_cpu() {
#if defined(__linux__)
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    if (::sched_getaffinity(0, sizeof(affinity), &affinity) == 0) {
        std::optional<std::uint64_t> selected;
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (!CPU_ISSET(cpu, &affinity)) {
                continue;
            }
            if (selected) {
                selected.reset();
                break;
            }
            selected = static_cast<std::uint64_t>(cpu);
        }
        if (selected) {
            return selected;
        }
    }
#endif
    const char *configured = std::getenv("LAMINATE_BENCH_CPU");
    if (configured == nullptr || *configured == '\0') {
        return std::nullopt;
    }
    std::istringstream input(configured);
    std::uint64_t result = 0;
    input >> result;
    return input && input.peek() == std::char_traits<char>::eof()
               ? std::optional<std::uint64_t>(result)
               : std::nullopt;
}

void emit_identity(const Record &record, const ProcessCommand &command,
                   const ProcessSetupRecord &setup) {
    const SystemInfo system = system_info();
    record.text("run.variant", command.variant_name);
    record.text("run.profile", command.profile_name);
    record.text("run.id", digest_hex(setup.run_id));
    record.text("protocol.variant", command.variant_name);
    record.text("protocol.gkr_claim_transition",
                std::string(gkr::kGkrClaimTransition));
    record.text("protocol.gkr_multiplication",
                std::string(gkr::kGkrMultiplicationReduction));
    record.text("protocol.fiat_shamir", std::string(kPackedFiatShamirSchedule));
    record.text("benchmark.profile", command.profile_name);
    record.text("benchmark.evidence",
                setup.diagnostic_stress_only
                    ? "reduced-security-stress-test"
                    : "evaluation");
    record.integer("security.transcript_packing.actual_repetitions",
                   setup.packing_repetitions);
    record.integer("security.transcript_packing.selected_repetitions",
                   setup.selected_packing_repetitions);
    record.integer("security.basefold.actual_queries",
                   setup.basefold_queries);
    record.integer("security.basefold.selected_queries",
                   setup.selected_basefold_queries);
    record.integer("security.basefold.log_rate",
                   setup.basefold_log_rate);
    record.integer("security.basefold.target_bits", kBaseFoldIntegrityTargetBits);
    record.text("security.basefold.bound_model", "unique-decoding-rbr");
    record.text("security.claim",
                setup.diagnostic_stress_only
                    ? "none-diagnostic-only"
                    : "selected-rbr-target-pending-composition");
    const gkr::CiphertextCommitmentPolicy ciphertext_hash =
        gkr::CiphertextCommitmentPolicy::from_wire_code(
            setup.ciphertext_commitment_policy_code);
    record.text(
        "protocol.ciphertext_hash",
        std::string(
            gkr::ciphertext_commitment_relation_name(ciphertext_hash)));
    record.text(
        "security.ciphertext_hash.claim",
        ciphertext_hash.is_diagnostic_only()
            ? "none-diagnostic-no-ciphertext-binding"
            : "poseidon-ciphertext-binding");
    record.text("environment.git_commit", setup.git_commit);
    record.text("environment.git_dirty",
                LAMINATE_PACKED_CHECKPOINT_GIT_DIRTY);
    record.text("environment.build_type", setup.build_type);
    record.text("environment.seal_acceleration", setup.seal_acceleration);
    record.text("environment.sha256_acceleration",
                LAMINATE_SHA256_ACCELERATION);
    record.text("environment.compiler", LAMINATE_COMPILER);
    record.text("environment.seal_version", LAMINATE_SEAL_VERSION);
    record.text("environment.fhe_backend", "seal-bgv");
    record.text("environment.trace_execution",
                "file-backed-checkpoint-replay");
    const auto execution = setup_execution(
        command.action == ProcessAction::Setup &&
        command.variant == PackedProcessVariant::Folded);
    record.integer("environment.worker_threads", execution.worker_threads);
    if (execution.worker_threads > 1) {
        record.text("environment.threading", "setup-worker-pool");
        record.text("environment.cpu_affinity", execution.cpu_affinity);
    } else {
        if (const auto cpu = pinned_logical_cpu()) {
            record.integer("environment.pinned_cpu", *cpu);
        } else {
            record.text("environment.pinned_cpu", "not-observed");
        }
        record.text("environment.threading", "single-cpu-process");
    }
    record.text("environment.os", system.os);
    record.text("environment.cpu", system.cpu);
    record.integer("environment.physical_cores", system.physical_cores);
    record.integer("environment.logical_cores", system.logical_cores);
    record.integer("environment.ram_bytes", system.ram_bytes);
    emit_cpu_feature_availability(record, system);
}

void emit_gate_mle_parameters(
    const Record &record, const gates::GateTableVerifierKey &key) {
    record.integer("parameters.gate_mle_basefold_log_rate",
                   key.basefold_parameters.log_rate);
    record.integer("parameters.gate_mle_basefold_queries",
                   laminate::bench::gate_mle_query_count(key));
    record.integer("security.basefold.gate_rbr_bits",
                   gate_mle_basefold_soundness_bits(key));
}

void emit_geometry(const Record &record, const ProcessSetupRecord &setup) {
    const BenchmarkPayloadProfile payload_profile =
        benchmark_payload_profile(setup.profile);
    record.integer("geometry.N", setup.slots);
    record.integer("geometry.B", setup.lanes);
    record.integer("geometry.depth", setup.multiplicative_depth);
    record.text("geometry.workload",
                std::string(workload_name(payload_profile.workload_kind)));
    record.integer("geometry.width", setup.middle_width);
    record.integer("geometry.payload_operations", setup.payload_operations);
    record.integer("geometry.payload_add_gates",
                   payload_profile.add_gates);
    record.integer("geometry.payload_add_plain_gates",
                   payload_profile.add_plain_gates);
    record.integer("geometry.payload_mul_gates",
                   payload_profile.mul_gates);
    record.integer("geometry.payload_mul_plain_gates",
                   payload_profile.mul_plain_gates);
    record.integer("geometry.payload_rotate_gates",
                   payload_profile.rotate_gates);
    record.integer("geometry.inputs", setup.input_ciphertexts);
    record.integer("geometry.outputs", setup.output_ciphertexts);
    record.integer("fhe.data_rns_limbs", setup.data_prime_bit_sizes.size());
    record.integer("fhe.plain_modulus", kBaseFieldOrder);
    record.text("fhe.data_prime_bit_sizes",
                join(setup.data_prime_bit_sizes));
    record.text("fhe.data_primes_bottom_to_top",
                join(setup.data_primes));
    record.integer("fhe.special_prime_bits", setup.special_prime_bits);
    record.integer("fhe.special_prime", setup.special_prime);
    record.integer("fhe.fresh_modulus_product_bits",
                   setup.fresh_modulus_product_bits);
    record.integer("fhe.key_modulus_product_bits",
                   setup.key_modulus_product_bits);
    std::vector<std::size_t> proof_ingress_limbs;
    proof_ingress_limbs.reserve(
        setup.evaluation_plan.proof_ingress_mult_depth_by_layer.size());
    for (const std::size_t depth :
         setup.evaluation_plan.proof_ingress_mult_depth_by_layer) {
        proof_ingress_limbs.push_back(depth + 1U);
    }
    // Layer zero is the output and never enters reverse GKR as a source.
    // Report the canonical committed placeholder, not its natural payload
    // level retained by the operational evaluation plan.
    proof_ingress_limbs.front() = 1U;
    record.text("schedule.policy", "committed-conservative-no-search");
    record.text("schedule.proof_ingress_policy",
                setup.proof_ingress_policy);
    record.text("schedule.proof_ingress_schedule_digest",
                digest_hex(setup.proof_ingress_schedule_digest));
    record.text("schedule.proof_ingress_rns_limbs_by_layer",
                join(proof_ingress_limbs));
    record.text("schedule.payload_modulus_switches_after_layer",
                join(setup.evaluation_plan.modulus_switches_after_layer));
}

void emit_packing_r1cs_geometry(
    const Record &record, std::string_view prefix,
    const PackedProcessR1csGeometry &geometry) {
    const auto key = [prefix](std::string_view suffix) {
        return std::string(prefix) + '.' + std::string(suffix);
    };
    const ProofOfPackingR1csLedger &ledger = geometry.ledger;
    const gkr::CiphertextCommitmentPolicy hash =
        gkr::CiphertextCommitmentPolicy::from_wire_code(
            geometry.ciphertext_commitment_policy_code);
    record.integer(key("ring_degree"), geometry.ring_degree);
    record.integer(key("repetitions"), geometry.repetitions);
    record.integer(key("aligned_ciphertexts"),
                   geometry.aligned_ciphertexts);
    record.integer(key("logical_packed_outputs"),
                   geometry.logical_packed_outputs);
    record.integer(key("physical_packed_ciphertexts"),
                   geometry.physical_packed_ciphertexts);
    record.integer(key("packing_digit_count"),
                   geometry.packing_digit_count);
    record.text(key("ciphertext_hash"),
                std::string(
                    gkr::ciphertext_commitment_relation_name(hash)));
    record.integer(
        key("ciphertext_commitment_constraints_per_ciphertext"),
        ledger.ciphertext_commitment_constraints_per_ciphertext);
    record.integer(key("ciphertext_commitment_constraints_total"),
                   ledger.ciphertext_commitment_constraints);
    record.integer(key("packing_relation_constraints"),
                   ledger.packing_relation_constraints);
    record.integer(key("active_constraints"),
                   ledger.total_constraints);
    record.integer(key("matrix_rows"), ledger.matrix_rows);
    record.integer(key("spartan_padded_constraints"),
                   geometry.padded_constraints);
    record.integer(key("public_inputs"), ledger.total_public_inputs);
    record.integer(key("active_witness_variables"),
                   ledger.active_witness_variables);
    record.integer(key("witness_extent"),
                   ledger.total_witness_variables);
    record.integer(key("spartan_assignment_half_size"),
                   geometry.assignment_half_size);
    record.integer(key("spartan_padded_assignment_variables"),
                   geometry.padded_assignment_variables);
}

void require_packing_r1cs_geometry_matches(
    const PackedProcessR1csGeometry &geometry,
    const ProofOfPackingStructuredMetadata &relation) {
    const auto &plan = relation.relation_plan;
    const auto &metadata = relation.circuit_metadata;
    ProofOfPackingR1csLedger dimension_ledger = relation.r1cs_ledger;
    dimension_ledger.ciphertext_poseidon_nonzero_entries_per_ciphertext = 0;
    dimension_ledger.ciphertext_poseidon_nonzero_entries = 0;
    dimension_ledger
        .ciphertext_commitment_nonzero_entries_per_ciphertext = 0;
    dimension_ledger.ciphertext_commitment_nonzero_entries = 0;
    dimension_ledger.packing_relation_nonzero_entries_upper_bound = 0;
    dimension_ledger.total_nonzero_entries_upper_bound = 0;
    dimension_ledger.nonzero_entry_counts_available = false;
    require(
        geometry.ring_degree == plan.shape.ring_degree &&
            geometry.repetitions == plan.shape.repetitions &&
            geometry.aligned_ciphertexts ==
                plan.shape.aligned_ciphertexts &&
            geometry.logical_packed_outputs ==
                plan.shape.logical_packed_outputs &&
            geometry.physical_packed_ciphertexts ==
                plan.physical_packed_ciphertexts() &&
            geometry.packing_digit_count ==
                plan.shape.packing_digit_count &&
            geometry.ciphertext_commitment_policy_code ==
                plan.shape.ciphertext_commitment_policy.wire_code() &&
            geometry.ledger == dimension_ledger &&
            metadata.shape().constraints == geometry.ledger.matrix_rows &&
            metadata.shape().public_inputs ==
                geometry.ledger.total_public_inputs &&
            metadata.shape().witness_variables ==
                geometry.ledger.total_witness_variables &&
            metadata.padded_constraints() ==
                geometry.padded_constraints &&
            metadata.assignment_half_size() ==
                geometry.assignment_half_size &&
            metadata.padded_variables() ==
                geometry.padded_assignment_variables,
        "formula-only packing R1CS geometry disagrees with setup");
}

struct ProcessCodecPolicy {
    std::size_t basefold_rbr_bits = 0;
    std::uint64_t request_wire_bytes = 0;
    std::uint64_t response_wire_bytes = 0;
    std::uint64_t ciphertext_wire_bytes = 0;
    std::uint64_t request_max_ciphertexts = 0;
    std::uint64_t response_max_ciphertexts = 0;
    std::uint64_t proof_max_ciphertexts = 0;
    std::uint64_t proof_max_collection_elements = 0;
    std::uint64_t proof_max_field_elements = 0;
    std::uint64_t proof_max_digests = 0;
};

/// Derive finite decoder budgets from the authenticated verifier shape. The
/// bounds deliberately charge every committed GKR message as a full N-slot
/// public vector and every reveal as a largest fresh-chain ciphertext. This
/// is conservative but remains proportional to the one proof being decoded;
/// host disk capacity never becomes a message-allocation authority.
template <typename GateShape>
ProcessCodecPolicy process_codec_policy_from_shape(
    const PackedProcessProfile &profile,
    const LayeredCircuit &circuit,
    const packing::OuterRelationPlan &relation_plan,
    const packing::LazyTernaryParameters &packing_parameters,
    const spartan::BaseFoldPcsParameters &basefold_parameters,
    const spartan::R1csMetadata &circuit_metadata,
    std::span<const spartan::FactoredTensorShape> tensor_shapes,
    const GateShape &gate_mle,
    const GateMleProverResourceBounds &gate_resources,
    std::size_t gate_soundness_bits) {
    // Take the maximum conditional error (minimum bit bound) over PCS
    // transitions. The enclosing VCoED state/binding proof is separate.
    std::size_t basefold_rbr_bits = gate_soundness_bits;
    const auto include_packing_opening = [&](std::size_t rows) {
        require(std::has_single_bit(rows),
                "BaseFold soundness requires power-of-two message rows");
        basefold_rbr_bits = std::min(basefold_rbr_bits,
            basefold::conservative_rbr_soundness_bound(
                std::bit_width(rows) - 1U, 0,
                basefold_parameters.log_rate, basefold_parameters.query_count,
                119).rbr_bits);
    };
    include_packing_opening(circuit_metadata.assignment_half_size());
    for (const auto &tensor : tensor_shapes) {
        include_packing_opening(tensor.evaluation_count);
    }
    require(profile.tier == PackedProcessTier::Quick ||
                basefold_rbr_bits >= kBaseFoldIntegrityTargetBits,
            "packed BaseFold shape does not meet the proven RBR target");
    constexpr std::uint64_t kCodecFramingAllowance = 4ULL << 20U;
    constexpr std::uint64_t kCiphertextFramingAllowance = 1ULL << 20U;
    constexpr std::uint64_t kFq2Bytes = 16;
    const std::uint64_t n = profile.slots;
    const std::uint64_t raw_fresh_ciphertext = checked_multiply(
        checked_multiply(2, n, "fresh ciphertext components"),
        checked_multiply(profile.fresh_rns_limbs(), sizeof(std::uint64_t),
                         "fresh ciphertext limbs"),
        "fresh ciphertext bytes");
    const std::uint64_t ciphertext = checked_add(
        raw_fresh_ciphertext, kCiphertextFramingAllowance,
        "ciphertext codec cap");
    const std::uint64_t aligned =
        relation_plan.shape.aligned_ciphertexts;
    const std::uint64_t packed_digits =
        relation_plan.physical_packed_ciphertexts();
    const std::uint64_t reveals = checked_add(
        packing_parameters.repetitions, packed_digits,
        "packed reveal count");

    const std::uint64_t row_variables =
        circuit_metadata.row_variables();
    const std::uint64_t column_variables =
        circuit_metadata.column_variables();
    std::uint64_t spartan_fields = checked_add(
        checked_multiply(2, checked_add(row_variables, column_variables,
                                        "Spartan sumcheck rounds"),
                         "Spartan sumcheck fields"),
        5, "Spartan terminal fields");
    std::uint64_t opening_bytes =
        spartan::basefold_opening_proof_max_size_bytes(
        std::bit_width(
            circuit_metadata.assignment_half_size()) - 1U,
        1U, basefold_parameters);
    std::uint64_t largest_collection = std::max<std::uint64_t>(
        {n, aligned, reveals, circuit.layers.size(), row_variables,
         column_variables, basefold_parameters.query_count});
    for (const auto &table : gate_mle.tables) {
        largest_collection = std::max<std::uint64_t>(
            {largest_collection, table.message_size,
             table.physical_width, table.logical_width});
    }
    largest_collection = std::max({
        largest_collection,
        packed_gate_mle_target_cell_limit(gate_mle),
        static_cast<std::uint64_t>(gate_mle.foldable_parameters.num_queries)});
    for (const auto &layer : gate_mle.layout.wide_layers)
        largest_collection = std::max(largest_collection,
            static_cast<std::uint64_t>(std::bit_width(layer.dimensions.internal_scalars) +
                                       basefold::foldable::kLogRate));
    if (!tensor_shapes.empty()) {
        largest_collection = std::max<std::uint64_t>(
            largest_collection, tensor_shapes.size());
        for (const spartan::FactoredTensorShape &shape : tensor_shapes) {
            require(shape.evaluation_count != 0 &&
                        std::has_single_bit(
                            shape.evaluation_count),
                    "factored verifier tensor has invalid shape");
            const std::uint64_t rounds =
                std::bit_width(shape.evaluation_count) - 1U;
            largest_collection = std::max(largest_collection, rounds);
            spartan_fields = checked_add(
                spartan_fields,
                checked_add(checked_multiply(2, rounds,
                                             "factored round fields"),
                            2, "factored terminal fields"),
                "Spartan field count");
            opening_bytes = checked_add(
                opening_bytes,
                spartan::basefold_opening_proof_max_size_bytes(
                    checked_size(rounds, "factored rounds"),
                    checked_size(shape.column_count,
                                 "factored columns"),
                    basefold_parameters),
                "BaseFold opening bytes");
        }
    }
    const std::uint64_t public_gkr_fields =
        checked_multiply(aligned, n, "public committed GKR fields");
    const std::uint64_t kGateMleProofAllowance =
        gate_resources.proof_bytes_upper_bound;
    largest_collection = std::max(largest_collection,
        kGateMleProofAllowance / sizeof(std::uint64_t));
    const std::uint64_t total_fields = checked_add(
        checked_add(public_gkr_fields, spartan_fields,
                    "packed proof field count"),
        checked_add(1024,
                    kGateMleProofAllowance / sizeof(std::uint64_t),
                    "packed GateMLE field allowance"),
        "packed proof field allowance");
    const std::uint64_t total_digests = checked_add(
        checked_add(aligned, tensor_shapes.size(),
                    "packed proof digest count"),
        checked_add(1024,
                    kGateMleProofAllowance / basefold::Digest{}.size(),
                    "packed GateMLE digest allowance"),
        "packed proof digest allowance");
    const std::uint64_t committed_bytes = checked_multiply(
        aligned, checked_add(checked_multiply(n, sizeof(std::uint64_t),
                                              "public message bytes"),
                             64, "public message framing"),
        "committed GKR bytes");
    const std::uint64_t reveal_bytes = checked_multiply(
        reveals, checked_add(ciphertext, 16, "reveal framing"),
        "packed reveal bytes");
    const std::uint64_t spartan_bytes = checked_add(
        checked_add(opening_bytes,
                    checked_multiply(spartan_fields, kFq2Bytes,
                                     "Spartan field bytes"),
                    "Spartan proof bytes"),
        kCodecFramingAllowance, "Spartan framing allowance");
    const std::uint64_t proof_bytes = checked_add(
        checked_add(
            checked_add(committed_bytes, reveal_bytes,
                        "packed proof bytes"),
            spartan_bytes, "packed proof bytes"),
        kGateMleProofAllowance, "packed GateMLE proof allowance");

    const std::uint64_t request_ciphertexts = profile.input_ciphertexts;
    const std::uint64_t response_ciphertexts = checked_add(
        profile.output_ciphertexts, reveals,
        "response ciphertext count");
    const std::uint64_t request_bytes = checked_add(
        checked_multiply(request_ciphertexts,
                         checked_add(ciphertext, 16,
                                     "request ciphertext framing"),
                         "request ciphertext bytes"),
        kCodecFramingAllowance, "request wire cap");
    const std::uint64_t response_bytes = checked_add(
        checked_add(
            checked_multiply(profile.output_ciphertexts,
                             checked_add(ciphertext, 16,
                                         "output ciphertext framing"),
                             "response output bytes"),
            proof_bytes, "response proof bytes"),
        kCodecFramingAllowance, "response wire cap");
    return {
        .basefold_rbr_bits = basefold_rbr_bits,
        .request_wire_bytes = request_bytes,
        .response_wire_bytes = response_bytes,
        .ciphertext_wire_bytes = ciphertext,
        .request_max_ciphertexts = request_ciphertexts,
        .response_max_ciphertexts = response_ciphertexts,
        .proof_max_ciphertexts = reveals,
        .proof_max_collection_elements = largest_collection,
        .proof_max_field_elements = total_fields,
        .proof_max_digests = total_digests,
    };
}

ProcessCodecPolicy process_codec_policy(
    const PackedProcessProfile &profile,
    const LayeredCircuit &circuit,
    const TranscriptPackingSpartanVerifierSetup &verifier,
    const gates::GateTableVerifierKey &gate_mle) {
    require(verifier.spartan.factored_computation != nullptr,
            "packed codec sizing requires a factored verifier key");
    std::vector<spartan::FactoredTensorShape> tensor_shapes;
    tensor_shapes.reserve(
        verifier.spartan.factored_computation->commitment.tensors.size());
    for (const auto &tensor :
         verifier.spartan.factored_computation->commitment.tensors) {
        tensor_shapes.push_back(tensor.shape);
    }
    return process_codec_policy_from_shape(
        profile, circuit, verifier.relation_plan, verifier.parameters,
        verifier.basefold_parameters, verifier.spartan.circuit_metadata,
        tensor_shapes, gate_mle, gate_mle_prover_resource_bounds(gate_mle),
        gate_mle_basefold_soundness_bits(gate_mle));
}

template <typename GateShape>
ProcessCodecPolicy process_codec_policy(
    const PackedProcessProfile &profile,
    const LayeredCircuit &circuit,
    const TranscriptPackingExternalPreprocessingSpecification &specification,
    const TranscriptPackingExternalPreprocessingPlan &plan,
    const GateShape &gate_mle,
    const GateMleProverResourceBounds &resources,
    std::size_t soundness_bits) {
    std::vector<spartan::FactoredTensorShape> tensor_shapes;
    tensor_shapes.reserve(plan.factored.tensors.size());
    for (const auto &tensor : plan.factored.tensors) {
        tensor_shapes.push_back(tensor.shape);
    }
    return process_codec_policy_from_shape(
        profile, circuit, plan.relation.relation_plan,
        specification.parameters, specification.basefold_parameters,
        plan.relation.circuit_metadata, tensor_shapes, gate_mle, resources, soundness_bits);
}

/// Value-free client peak used before SEAL keys exist. Each term is the same
/// ownership category charged by `process_ram_policy`: restored client and
/// verifier contexts, decoded static state, the larger request/response codec
/// peak, and process slack. Exact setup must refine this bound downward before
/// selecting its final replay plan.
std::uint64_t conservative_adaptive_client_peak_resident_bytes(
    const PackedProcessProfile &profile,
    std::uint64_t workload_bytes,
    const ProcessCodecPolicy &codec) {
    const std::uint64_t restored_fhe_contexts = checked_multiply(
        2, conservative_adaptive_client_fhe_bundle_bytes(profile),
        "conservative restored client contexts");
    const std::uint64_t decoded_static = checked_add(
        workload_bytes, kClientRoleStaticReserveBytes,
        "conservative decoded client static state");
    const std::uint64_t codec_peak = checked_multiply(
        2, std::max(codec.request_wire_bytes, codec.response_wire_bytes),
        "conservative client codec peak");
    return checked_add(
        checked_add(restored_fhe_contexts, decoded_static,
                    "conservative client static resident reserve"),
        checked_add(codec_peak, kResidentSafetySlack,
                    "conservative client codec and slack reserve"),
        "conservative client peak resident reserve");
}

ProcessSetupRecord packed_planning_record(
    const PackedProcessProfile &profile,
    const PayloadCheckpointReplayProblem &problem,
    const GateMleProverResourceBounds &gate,
    std::uint64_t affine_workspace, const ProcessCodecPolicy &codec,
    const HostResourceBudget &host_budget, std::uint64_t workload_bytes) {
    ProcessSetupRecord record;
    record.variant = profile.variant == PackedProcessVariant::Folded ? "folded" : "laned";
    record.slots = profile.slots;
    record.lanes = profile.lanes;
    record.replay_problem = problem;
    record.host_budget = host_budget;
    record.workload_max_bytes = workload_bytes;
    record.request_wire_bytes = codec.request_wire_bytes;
    record.response_wire_bytes = codec.response_wire_bytes;
    record.ciphertext_wire_bytes = codec.ciphertext_wire_bytes;
    record.gate_mle_retained_prover_key_bytes = gate.retained_prover_key_bytes;
    record.gate_mle_opening_workspace_bytes = gate.opening_workspace_bytes;
    record.gate_mle_retained_prover_key_disk_bytes = gate.retained_prover_key_disk_bytes;
    record.gate_mle_opening_workspace_disk_bytes = gate.opening_workspace_disk_bytes;
    record.gate_mle_affine_preparation_workspace_bytes = affine_workspace;
    record.capacity = process_capacity(host_budget, 0,
        process_ram_policy(record).client_peak_bytes);
    return record;
}

struct PackedStructuralPreflight {
    GateMlePreprocessingPlan gate;
    TranscriptPackingExternalPreprocessingPlan packing;
    std::uint64_t server_resident_floor = 0;
    std::uint64_t server_common_disk_floor = 0;
    std::uint64_t minimum_builder_peak = 0;
    std::uint64_t replay_work_units = 0;
    std::uint64_t selected_required_available_disk_bytes = 0;
    EagerLanedWitnessPackingAdmission eager_laned;
    std::uint64_t server_resident_cap = 0;
};

// Admit circuit geometry, commitment sizes, wire caps, and bounded GKR
// workspaces before creating keys or commitment files. Refine the admission
// with exact FHE-bundle and authenticated static sizes before publishing the
// transcript-packing artifacts.
PackedStructuralPreflight plan_packed_structural_preflight(
    const PackedProcessProfile &profile, const PayloadCircuit &payload,
    const LayeredCircuit &circuit, const HostResourceBudget &host_budget,
    const std::filesystem::path &gate_scratch_parent) {
    PackedStructuralPreflight result;
    result.gate = plan_gate_mle_preprocessing(circuit,
        profile.variant == PackedProcessVariant::Laned
            ? gates::GateTableSet::Laned : gates::GateTableSet::Wide,
        gates::GateTableBuildOptions{
            .wide_scratch_parent = gate_scratch_parent,
            .wide_max_disk_bytes = host_budget.max_live_disk_bytes,
            .wide_resources = {.min_free_bytes = kBenchmarkFreeDiskReserveBytes}});
    const std::uint64_t live_key_reserve =
        packed_process_uses_folded_pyramid_headroom(profile)
            ? std::uint64_t{16} << 30U : 0;
    require(checked_add(live_key_reserve,
                checked_add(result.gate.resources.retained_prover_key_bytes,
                            result.gate.resources.opening_workspace_bytes,
                            "early GateMLE RAM floor"),
                "GateMLE plus retained live-key RAM floor") <= host_budget.max_resident_ram_bytes,
            "packed structural preflight: GateMLE RAM exceeds the host budget");
    const auto unbound_setup = make_direct_setup(payload, circuit);
    const auto ingress = derive_conservative_packed_proof_ingress_schedule(
        packing_variant(profile.variant), payload, circuit, unbound_setup,
        packed_process_proof_ingress_policy(profile));
    const auto evaluation = evaluation_plan(profile, circuit, ingress);
    const auto trace = derive_certified_canonical_trace_layout(circuit);
    const auto problem = replay_problem(trace, evaluation, profile.fresh_rns_limbs());
    MultiplicationWorkspaceBounds exact_workspaces;
    const auto scratch = multiplication_scratch_caps(
        circuit, trace.layout(), problem, host_budget.max_live_disk_bytes,
        &exact_workspaces);
    const auto specification = packing_specification(profile, circuit);
    result.packing = plan_transcript_packing_external_preprocessing(specification);
    const auto &packing = result.packing;
    const auto codec = process_codec_policy(profile, circuit, specification, packing,
        result.gate, result.gate.resources, result.gate.basefold_soundness_bits);
    const auto workload_floor = checked_add(
        payload::encode_canonical(payload).size(),
        payload::encode_canonical(circuit).size(), "packed workload encoding floor");
    result.server_common_disk_floor = checked_add(
        packing.factored.persistent_output_physical_bytes,
        checked_add(workload_floor,
            checked_add(checked_add(codec.request_wire_bytes, codec.response_wire_bytes,
                                    "structural transport disk reserve"),
                        kOnlineMetadataDiskReserve, "structural metadata disk reserve"),
            "structural workload and transport disk reserve"),
        "structural server common disk floor");
    require(result.server_common_disk_floor <= kPackedAdaptiveServerCommonDiskReserveBytes,
            "packed structural preflight: known packing, transport, and static disk exceed the common reserve");
    auto record = packed_planning_record(profile, problem, result.gate.resources,
        affine_gate_preparation_workspace_bytes(circuit), codec, host_budget,
        workload_floor);
    const auto conservative_client_ram = conservative_adaptive_client_peak_resident_bytes(
        profile, workload_floor, codec);
    record.capacity = process_capacity(host_budget,
        conservative_adaptive_client_private_persistent_bytes(profile),
        conservative_client_ram);
    const auto scalar_workspaces = multiplication_workspace_bounds(record);
    require(scalar_workspaces.builder >= exact_workspaces.builder &&
                scalar_workspaces.reduction >= exact_workspaces.reduction,
            "packed multiplication scalar workspace bounds omit alias resources");
    const auto ram = process_ram_policy(record);
    const auto fixed = checked_add(ram.server_common_bytes,
        ram.server_payload_gkr_only_bytes, "packed structural resident floor");
    result.server_resident_floor = fixed;
    result.minimum_builder_peak = checked_add(fixed,
        checked_add(ram.reduction_workspace_bytes,
            checked_add(multiplication_workspace_bounds(record).builder,
                2 * gkr::detail::kDenseMultiplicationSortMaxBufferedPayloadBytes,
                "packed structural builder floor"),
            "packed structural builder floor"),
        "packed structural builder floor");
    // The same selector is called again with exact context and static sizes.
    (void)process_multiplication_sort_buffer_bytes(record);
    require(checked_add(ram.server_common_bytes, ram.server_packing_only_bytes,
                        "packed structural packing RAM") <=
                record.capacity.max_resident_ram_bytes,
            "packed structural preflight: transcript-packing RAM exceeds the server cap");
    require(result.gate.commitment_peak_disk_bytes <= host_budget.max_live_disk_bytes,
            "packed structural preflight: GateMLE construction exceeds the disk cap");
    require(checked_add(packing.factored.conservative_peak_live_physical_bytes,
                        result.gate.resources.retained_prover_key_disk_bytes,
                        "packed construction disk floor") <= host_budget.max_live_disk_bytes,
            "packed structural preflight: transcript-packing construction exceeds the disk cap");
    const auto replay = plan_packed_adaptive_storage_preflight(problem, scratch,
        host_budget, conservative_adaptive_client_private_persistent_bytes(profile),
        conservative_client_ram,
        checked_add(result.gate.resources.retained_prover_key_disk_bytes,
                    result.gate.resources.opening_workspace_disk_bytes,
                    "early GateMLE disk reserve"), fixed);
    result.server_resident_cap = replay.replay_budgets.max_resident_ciphertext_bytes;
    if (profile.variant == PackedProcessVariant::Laned) {
        result.eager_laned = admit_eager_laned_witness_packing(
            circuit, problem, replay.replay_budgets, replay.replay);
    }
    result.replay_work_units = replay.replay.selected.replay_work_units;
    result.selected_required_available_disk_bytes = checked_add(
        replay.replay.selected.peak_live_scratch_bytes,
        checked_add(conservative_adaptive_client_private_persistent_bytes(profile),
                    kBenchmarkFreeDiskReserveBytes,
                    "selected replay client and free-disk reserve"),
        "selected replay available disk requirement");
    if (profile.tier != PackedProcessTier::Quick && result.replay_work_units != 0) {
        auto zero_replay_budgets = replay.replay_budgets;
        zero_replay_budgets.max_live_scratch_bytes =
            std::numeric_limits<std::uint64_t>::max();
        const auto zero_replay = plan_payload_checkpoint_replay(problem, zero_replay_budgets);
        if (zero_replay.selected.replay_work_units != 0) {
            throw std::runtime_error(
                "packed structural preflight: target RAM requires payload replay even with unlimited disk; "
                "zero-replay reference RAM=" +
                std::to_string(replay.replay.full_trace_reference.peak_resident_bytes) +
                ", RAM cap=" + std::to_string(replay.replay_budgets.max_resident_ciphertext_bytes));
        }
        const auto required_available = checked_add(
            zero_replay.selected.peak_live_scratch_bytes,
            checked_add(conservative_adaptive_client_private_persistent_bytes(profile),
                        kBenchmarkFreeDiskReserveBytes,
                        "zero-replay client and free-disk reserve"),
            "zero-replay available disk requirement");
        throw std::runtime_error(
            "packed structural preflight: target capacity requires payload replay; "
            "selected replay work=" + std::to_string(result.replay_work_units) +
            ", zero-replay required available disk=" + std::to_string(required_available) +
            ", available disk=" + std::to_string(host_budget.observed_available_disk_bytes) +
            // Keep optional payload caches bounded to the supplied host;
            // unbounded RAM would admit caches that zero replay does not require.
            ", zero-replay reference RAM=" +
                std::to_string(replay.replay.full_trace_reference.peak_resident_bytes) +
            ", RAM cap=" + std::to_string(replay.replay_budgets.max_resident_ciphertext_bytes));
    }
    return result;
}

int run_build_info() {
    Writer writer;
    writer.text(kSetupDomain);
    writer.u64(kSetupVersion);
    Reader reader(writer.view());
    if (reader.text("self-test domain") != kSetupDomain ||
        reader.u64("self-test version") != kSetupVersion) {
        throw std::logic_error("packed process codec self-check failed");
    }
    reader.require_end();
    std::cout
        << "format=laminate-packed-checkpoint-build-info-v1\n"
        << "environment.git_commit="
        << LAMINATE_PACKED_CHECKPOINT_GIT_COMMIT << '\n'
        << "environment.git_dirty="
        << LAMINATE_PACKED_CHECKPOINT_GIT_DIRTY << '\n'
        << "environment.build_type=" << LAMINATE_BUILD_TYPE << '\n'
        << "environment.seal_acceleration="
        << LAMINATE_SEAL_ACCELERATION << '\n'
        << "environment.sha256_acceleration="
        << LAMINATE_SHA256_ACCELERATION << '\n'
        << "protocol.variants=folded,laned\n"
        << "campaign.target-balancedLaned.variants=folded,laned\n"
        << "campaign.target-mulHeavyPyramid.variants=folded\n"
        << "campaign.laned.lanes=1,128,16384\n"
        << "protocol.exchange=one-request-one-response\n"
        << "protocol.fiat_shamir=" << kPackedFiatShamirSchedule << '\n'
        << "protocol.gkr_claim_transition=" << gkr::kGkrClaimTransition << '\n'
        << "protocol.gkr_multiplication=" << gkr::kGkrMultiplicationReduction << '\n'
        << "schedule.policy=committed-conservative-no-search\n"
        << "profile.quick.packing_repetitions=4\n"
        << "profile.target-balancedLaned.packing_repetitions=120\n"
        << "profile.target-mulHeavyPyramid.packing_repetitions=120\n"
        << "profile.quick.basefold_queries=4\n"
        << "profile.target-balancedLaned.basefold_queries="
        << kTranscriptPackingBaseFoldQueries << '\n'
        << "profile.target-mulHeavyPyramid.basefold_queries="
        << kTranscriptPackingBaseFoldQueries << '\n'
        << "profile.basefold_log_rate="
        << kTranscriptPackingBaseFoldLogRate << '\n'
        << "profile.gate_mle=folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold\n"
        << "profile.quick.ciphertext_hash=simpleCTHash/v2\n"
        << "profile.target-balancedLaned.ciphertext_hash=poseidon/v2\n"
        << "profile.target-mulHeavyPyramid.ciphertext_hash=poseidon/v2\n"
        << "profile.target-balancedLaned.admitted=true\n"
        << "profile.target-mulHeavyPyramid.admitted=true\n";
    return 0;
}

int run_setup(const ProcessCommand &command, int argc, char **argv) {
    const auto execution = setup_execution(
        command.variant == PackedProcessVariant::Folded);
    const PackedProcessProfile profile =
        packed_process_profile(command.variant, command.tier,
                               command.lanes);
    // These exact formulas are deliberately evaluated before the measured
    // setup interval. The actual geometry is checked later against the
    // independently compiled and setup-bound relation. The selected-target
    // projection never constructs the target payload circuit or R1CS.
    const PackedProcessR1csGeometry actual_r1cs =
        packed_process_r1cs_geometry(profile);
    const PackedProcessProfile selected_target = packed_process_profile(
        command.variant,
        profile.evidence == PackedProcessEvidence::Evaluation
            ? command.tier
            : PackedProcessTier::TargetBalanced,
        command.lanes);
    const PackedProcessR1csGeometry selected_target_r1cs =
        packed_process_r1cs_geometry(selected_target);
    // This check deliberately precedes build checks, directory creation,
    // activity files, and failure publication.
    require_profile_execution_policy_before_artifacts(profile);
    require_build_for_setup();
    const std::int64_t setup_started = unix_milliseconds();
    create_run_tree(command.run_directory);
    const Digest run_id = random_digest();
    publish_run_binding(command, run_id);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "shared" /
                              "setup-activity.jsonl",
                          "setup");
    Stopwatch total_stopwatch;
    Stopwatch workload_stopwatch;
    Timing fhe_preprocessing_timing;
    Timing packed_preprocessing_timing;
    Timing live_key_preflight_timing;
    std::optional<SealBackend::Contexts> preflight_contexts;
    const bool require_live_key_preflight =
        profile.variant == PackedProcessVariant::Folded &&
        profile.tier == PackedProcessTier::TargetMulHeavy;

    // Step 1: Freeze the planner budget before compiling the workload or
    // constructing cryptographic preprocessing. Profile geometry remains
    // fixed; only checkpoint placement adapts to the host.
    activity.transition("deriving_host_resource_budget");
    std::error_code space_error;
    const std::filesystem::space_info space =
        std::filesystem::space(command.run_directory, space_error);
    require(!space_error &&
                space.available <= std::numeric_limits<std::uint64_t>::max(),
            "failed to inspect benchmark filesystem capacity");
    const SystemInfo host = system_info();
    require(host.ram_bytes != 0,
            "failed to inspect benchmark physical RAM");
    const HostResourceBudget host_budget = derive_host_resource_budget(
        static_cast<std::uint64_t>(space.available), host.ram_bytes);
    ProcessCapacity capacity = process_capacity(host_budget);
    const std::uint64_t conservative_client_private_persistent_bytes =
        conservative_adaptive_client_private_persistent_bytes(profile);
    std::cout
        << "SETUP: host-derived planner budget reserves "
        << kBenchmarkFreeDiskReserveBytes << " disk bytes and "
        << kBenchmarkOperatingSystemRamReserveBytes << " OS RAM bytes plus "
        << kBenchmarkPageCacheRamReserveBytes << " page-cache bytes; "
        << capacity.max_live_disk_bytes << " gross live-disk bytes and "
        << capacity.max_resident_ram_bytes
        << " gross resident bytes remain after the fixed reserves; "
        << conservative_client_private_persistent_bytes
        << " bytes are reserved for client-private preprocessing before "
           "server checkpoint planning\n"
        << std::flush;

    activity.transition("constructing_payload_workload");
    PayloadCircuit payload = make_payload_circuit(workload_spec(profile));
    const PayloadStats payload_stats = analyze(payload);
    const BenchmarkPayloadProfile payload_profile =
        benchmark_payload_profile(profile.tier);
    require(payload.input_count == profile.input_ciphertexts &&
                payload.outputs.size() == profile.output_ciphertexts &&
                payload.gates.size() == profile.payload_operations &&
                payload_stats.add_gates == payload_profile.add_gates &&
                payload_stats.add_plain_gates ==
                    payload_profile.add_plain_gates &&
                payload_stats.mul_gates == payload_profile.mul_gates &&
                payload_stats.ct_ct_multiplicative_depth ==
                    profile.multiplicative_depth,
            "payload workload geometry drifted");

    activity.transition("compiling_payload_once");
    LayeredCircuit circuit = compile(payload);
    activity.transition("checking_structural_resources_before_commitments");
    std::cout << "SETUP: checking circuit, GateMLE, replay and GKR resource bounds before commitments" << std::endl;
    auto structural_preflight = plan_packed_structural_preflight(
        profile, payload, circuit, host_budget,
        command.run_directory / "shared" / "gate-mle-scratch");
    std::cout << "SETUP: structural resource preflight PASS; minimum multiplication-builder peak "
              << structural_preflight.minimum_builder_peak << " bytes" << std::endl;
    if (require_live_key_preflight) {
        // These exact keys survive into the role bundles below. Admission is
        // fail-closed: a rejected key is never replaced or retried here.
        activity.transition("target_packed_live_key_noise_preflight");
        Stopwatch preflight_stopwatch;
        preflight_contexts.emplace(SealBackend::create(seal_parameters(profile)));
        const auto unbound_setup = make_direct_setup(payload, circuit);
        const auto preflight_ingress = derive_conservative_packed_proof_ingress_schedule(
            packing_variant(profile.variant), payload, circuit, unbound_setup,
            packed_process_proof_ingress_policy(profile));
        const auto preflight_plan = evaluation_plan(profile, circuit, preflight_ingress);
        require_folded_pyramid_live_key_preflight(
            payload, circuit, make_workload_inputs(workload_spec(profile)),
            preflight_contexts->eval, preflight_contexts->client, preflight_plan,
            command.run_directory / "shared" / "live-key-noise-preflight-scratch",
            capacity.max_resident_ram_bytes, std::cout);
        live_key_preflight_timing = preflight_stopwatch.stop();
    }
    activity.transition("preprocessing_structured_gate_mle");
    std::cout << "SETUP: GateMLE preprocessing uses "
              << execution.worker_threads << " worker(s)" << std::endl;
    OutsourcedGateMleSetupArtifacts gate_mle =
        preprocess_outsourced_gate_mle_setup(
            payload, circuit,
            profile.variant == PackedProcessVariant::Laned
                ? gates::GateTableSet::Laned
                : gates::GateTableSet::Wide,
            gates::GateTableBuildOptions{
                .wide_scratch_parent = command.run_directory / "shared" / "gate-mle-scratch",
                .wide_max_disk_bytes = capacity.max_live_disk_bytes,
                .wide_resources = {.min_free_bytes = capacity.min_free_disk_bytes},
                .preprocessing_threads = execution.worker_threads,
                .prover_key_directory = command.run_directory / "server" / "preprocessing" / "gate-mle"});
    PublicSetup public_setup = std::move(gate_mle.public_setup);
    // Durable opening state belongs only to the server. The client receives
    // its compact verifier projection; startup reopens the saved state.
    gate_mle.prover_key.reset();
    CertifiedPackedWorkloadStatic certified =
        certify_packed_workload_static(
            std::move(payload), std::move(circuit),
            std::move(public_setup));
    const std::size_t compiled_bhip_rounds =
        profile.variant == PackedProcessVariant::Folded
            ? folded_bhip_round_count(certified.circuit())
            : laned_bhip_round_count(certified.circuit());
    require(compiled_bhip_rounds == actual_r1cs.aligned_ciphertexts,
            "compiled payload BhIP count disagrees with formula");
    const std::vector<std::uint8_t> workload_encoding =
        encode_packed_workload_static(certified);
    const PackedWorkloadStaticDecodeLimits workload_decode_requirements =
        packed_workload_static_decode_requirements(
            certified, workload_encoding.size());
    activity.transition("validating_workload_decode_contract");
    (void)decode_authenticated_packed_workload_static(
        workload_encoding, sha256(workload_encoding),
        certified.semantic_identity(), workload_decode_requirements);

    activity.transition("deriving_fixed_packed_schedule");
    const ConservativePackedProofIngressSchedule ingress =
        derive_conservative_packed_proof_ingress_schedule(
            packing_variant(profile.variant), certified.payload(),
            certified.circuit(), certified.public_setup(),
            packed_process_proof_ingress_policy(profile));
    FheEvaluationPlan evaluation =
        evaluation_plan(profile, certified.circuit(), ingress);
    evaluation.validate(certified.circuit());
    PayloadCheckpointReplayProblem problem = replay_problem(
        certify_canonical_trace_layout(certified.circuit(), certified.trace_layout()),
        evaluation, profile.fresh_rns_limbs());
    const TranscriptPackingExternalPreprocessingSpecification specification =
        packing_specification(profile, certified.circuit());
    const TranscriptPackingExternalPreprocessingPlan packing_formula_plan =
        std::move(structural_preflight.packing);
    const Timing workload_timing = workload_stopwatch.stop();

    Stopwatch storage_preflight_stopwatch;
    const std::vector<std::uint64_t> scratch_caps =
        multiplication_scratch_caps(certified.circuit(), certified.trace_layout(), problem,
                                    capacity.max_live_disk_bytes);

    // Use the exact compiled trace to derive the minimum-work replay schedule
    // that fits the setup-bound host budget. GateMLE preprocessing is already
    // available; this check precedes SEAL contexts, ciphertexts, checkpoints,
    // and transcript-packing artifacts.
    const GateMleProverResourceBounds gate_mle_resources =
        gate_mle_prover_resource_bounds(
            *certified.public_setup().outsourced_gate_mle);

    require(gate_mle_resources == structural_preflight.gate.resources,
            "committed GateMLE resources differ from the structural preflight");
    const ProcessCodecPolicy conservative_codec = process_codec_policy(
        profile, certified.circuit(), specification, packing_formula_plan,
        *certified.public_setup().outsourced_gate_mle,
        gate_mle_resources,
        gate_mle_basefold_soundness_bits(*certified.public_setup().outsourced_gate_mle));
    const std::uint64_t conservative_client_peak_resident_bytes =
        conservative_adaptive_client_peak_resident_bytes(
            profile, workload_encoding.size(), conservative_codec);
    activity.transition("planning_checkpoint_replay");
    const PackedAdaptiveStoragePreflight adaptive_storage_preflight =
        plan_packed_adaptive_storage_preflight(
            problem, scratch_caps, host_budget,
            conservative_client_private_persistent_bytes,
            conservative_client_peak_resident_bytes,
            checked_add(
                gate_mle_resources.retained_prover_key_disk_bytes,
                gate_mle_resources.opening_workspace_disk_bytes,
                "early GateMLE disk reserve"),
            structural_preflight.server_resident_floor);
    {
        const auto &selected = adaptive_storage_preflight.replay.selected;
        const double recomputation_factor =
            static_cast<double>(selected.cumulative_work_units) /
            static_cast<double>(selected.initial_forward_work_units);
        std::cout
            << "SETUP: host-adaptive storage preflight PASS\n"
            << "  available filesystem bytes: "
            << host_budget.observed_available_disk_bytes << '\n'
            << "  gross live-disk budget: "
            << host_budget.max_live_disk_bytes
            << " (observed available minus 100 GB free floor)\n"
            << "  conservative client-private persistence: "
            << conservative_client_private_persistent_bytes << " bytes\n"
            << "  server live-disk budget after that reserve: "
            << adaptive_storage_preflight.replay_budgets
                   .max_live_scratch_bytes
            << " bytes\n"
            << "  observed physical RAM: "
            << host_budget.observed_physical_ram_bytes << '\n'
            << "  gross resident budget: "
            << host_budget.max_resident_ram_bytes
            << " (observed physical RAM minus 16 GB host reserve)\n"
            << "  conservative concurrent-client resident reserve: "
            << conservative_client_peak_resident_bytes << " bytes\n"
            << "  server resident budget after that reserve: "
            << adaptive_storage_preflight.replay_budgets
                   .max_resident_ciphertext_bytes
            << " bytes\n"
            << "  conservative server-common reserve: "
            << kPackedAdaptiveServerCommonDiskReserveBytes << " bytes\n"
            << "  selected checkpoints: "
            << selected.checkpoint_layers.size() << " ("
            << selected.checkpoint_bytes << " bytes)\n"
            << "  selected replay peak: "
            << selected.peak_live_scratch_bytes << " bytes\n"
            << "  cumulative payload-work factor: "
            << std::fixed << std::setprecision(4)
            << recomputation_factor << "x (limit 2.5x)\n"
            << std::defaultfloat << std::setprecision(6) << std::flush;
    }
    const Timing storage_preflight_timing =
        storage_preflight_stopwatch.stop();

    Digest context_id{};
    Digest fixed_basis_id{};
    Digest root_storage_identity{};
    std::vector<std::uint64_t> actual_data_primes;
    std::uint64_t actual_special_prime = 0;
    std::uint64_t fresh_modulus_product_bits = 0;
    std::uint64_t key_modulus_product_bits = 0;
    std::uint64_t fixed_basis_ntt_bytes = 0;
    BundleBinding evaluation_binding;
    BundleBinding client_binding;
    BundleBinding verifier_binding;
    BundleBinding fixed_basis_binding;
    PackedRolePreprocessingPublishLimits publication_limits;
    PackedRolePreprocessingOpenLimits opening_limits;
    PackedRolePreprocessingPublicationPlan publication_plan;
    TranscriptPackingExternalPreprocessingReport packing_setup_report;
    PackedSetupPrepublicationAdmission setup_prepublication_admission;

    // This scope is the setup producer. Only authenticated bytes and compact
    // scalar bindings cross its boundary; neither keys nor live protocol
    // state survive into the validation phase below.
    {
        Stopwatch fhe_stopwatch;
        activity.transition(preflight_contexts ? "reusing_preflight_seal_contexts"
                                               : "creating_seal_contexts");
        SealBackend::Contexts contexts = preflight_contexts
            ? std::move(*preflight_contexts)
            : SealBackend::create(seal_parameters(profile));
        preflight_contexts.reset();
        context_id = SealBackend::storage_context_id(contexts.eval);
        actual_data_primes = SealBackend::coefficient_moduli(contexts.eval);
        require(actual_data_primes.size() ==
                    profile.fresh_rns_limbs() + 1U,
                "SEAL context has an unexpected coefficient-modulus count");
        actual_special_prime = actual_data_primes.back();
        actual_data_primes.pop_back();
        fresh_modulus_product_bits =
            NaturalMagnitude::product(actual_data_primes).bit_count();
        key_modulus_product_bits =
            SealBackend::key_modulus_bits(contexts.eval);
        SealBackend::PublicVerifierContext verifier =
            SealBackend::make_public_verifier_context(contexts.client);

        activity.transition("preprocessing_fixed_message_basis");
        SealBackend::preprocess_fixed_message_cells(contexts.eval);
        fixed_basis_ntt_bytes =
            SealBackend::plaintext_preprocessing_stats(contexts.eval)
                .ntt_coefficient_bytes;
        require(fixed_basis_ntt_bytes != 0,
                "fixed-message preprocessing produced no NTT coefficients");
        const std::vector<std::uint8_t> evaluation_bytes =
            SealBackend::serialize_evaluation_context_bundle(contexts.eval);
        const std::vector<std::uint8_t> client_bytes =
            SealBackend::serialize_client_context_bundle(contexts.client);
        const std::vector<std::uint8_t> verifier_bytes =
            SealBackend::serialize_public_verifier_context_bundle(verifier);
        const std::vector<std::uint8_t> fixed_basis_bytes =
            SealBackend::serialize_fixed_message_cell_preprocessing(
                contexts.eval);
        fixed_basis_id =
            SealBackend::fixed_message_cell_preprocessing_artifact_id(
                fixed_basis_bytes);

        activity.transition("publishing_fhe_role_bundles");
        evaluation_binding = publish_bundle(
            command.run_directory / "server" / "preprocessing" /
                "evaluation-context.bin",
            evaluation_bytes);
        client_binding = publish_bundle(
            command.run_directory / "client" / "preprocessing" /
                "client-context.bin",
            client_bytes);
        verifier_binding = publish_bundle(
            command.run_directory / "client" / "preprocessing" /
                "public-verifier-context.bin",
            verifier_bytes);
        fixed_basis_binding = publish_bundle(
            command.run_directory / "server" / "preprocessing" /
                "fixed-message-basis.bin",
            fixed_basis_bytes);
        fhe_preprocessing_timing = fhe_stopwatch.stop();

        Stopwatch packed_stopwatch;
        activity.transition("planning_external_transcript_packing");
        publication_plan = plan_packed_role_preprocessing_publication(
            certified, specification, context_id);
        {
            require(publication_plan.client_role_static_bytes <=
                        kClientRoleStaticReserveBytes &&
                        publication_plan.client_artifacts.serialized_bytes ==
                            0,
                    "adaptive client role publication exceeds its "
                    "formula-only persistence reserve");
        }
        require(specification.bhip_round_count == compiled_bhip_rounds,
                "packing specification changed the compiled BhIP count");
        require_packing_r1cs_geometry_matches(
            actual_r1cs,
            publication_plan.transcript_packing.relation);
        require(publication_plan.workload_decode_requirements ==
                    workload_decode_requirements,
                "packed workload decode requirements drifted");
        publication_limits = role_publication_limits(
            certified, publication_plan, capacity.min_free_disk_bytes);
        opening_limits =
            packed_role_preprocessing_open_limits(publication_limits);

        activity.transition("admitting_external_role_preprocessing");
        const PackedSetupPrepublicationDemand setup_demand =
            packed_setup_prepublication_demand(
                evaluation_binding, client_binding, verifier_binding,
                fixed_basis_binding, workload_encoding.size(),
                publication_plan, publication_limits, gate_mle_resources,
                regular_file_bytes(command.run_directory / "server" /
                                   "preprocessing" / "gate-mle"));
        // At this boundary every online RAM term is known exactly. Check
        // replay and GKR admission before producing the large packing tree.
        {
            auto planned = packed_planning_record(profile, problem, gate_mle_resources,
                affine_gate_preparation_workspace_bytes(certified.circuit()),
                conservative_codec, host_budget, workload_encoding.size());
            planned.evaluation_bundle = evaluation_binding;
            planned.client_bundle = client_binding;
            planned.verifier_bundle = verifier_binding;
            planned.fixed_message_basis_ntt_bytes = fixed_basis_ntt_bytes;
            planned.role_static_max_bytes = publication_limits.storage.max_role_artifact_bytes;
            planned.multiplication_scratch_bytes_by_reduction = scratch_caps;
            const auto exact_ram = process_ram_policy(planned);
            planned.capacity = process_capacity(host_budget,
                conservative_client_private_persistent_bytes, exact_ram.client_peak_bytes);
            planned.server_common_resident_bytes = exact_ram.server_common_bytes;
            planned.server_payload_gkr_only_resident_bytes = exact_ram.server_payload_gkr_only_bytes;
            planned.server_packing_only_resident_bytes = exact_ram.server_packing_only_bytes;
            planned.reduction_workspace_resident_bytes = exact_ram.reduction_workspace_bytes;
            planned.client_peak_resident_bytes = exact_ram.client_peak_bytes;
            planned.replay_budgets = replay_budgets(planned.capacity,
                checked_add(
                    checked_add(setup_demand.final_persistent_bytes,
                        gate_mle_resources.opening_workspace_disk_bytes,
                        "prepublication server disk reserve"),
                    checked_add(checked_add(planned.request_wire_bytes,
                                             planned.response_wire_bytes,
                                             "prepublication transport reserve"),
                                kOnlineMetadataDiskReserve,
                                "prepublication transport reserve"),
                    "prepublication server disk reserve"), planned);
            const auto replay = plan_payload_checkpoint_replay(problem, planned.replay_budgets);
            require(profile.tier == PackedProcessTier::Quick || replay.selected.replay_work_units == 0,
                    "packed prepublication preflight: target capacity requires payload replay");
            OnlineRoots roots;
            for (std::size_t layer = 0; layer + 1U < certified.circuit().layers.size(); ++layer)
                if (layer_kind(certified.circuit().layers[layer]) == LayerKind::Multiplication)
                    roots.gkr_multiplications.emplace_back("unused-preflight-root");
            auto limits = server_storage_limits(certified.circuit(), planned);
            if (profile.variant == PackedProcessVariant::Folded) {
                const auto options = folded_gkr_options(certified.circuit(), roots, planned);
                (void)admit_checkpoint_replay_server_storage(problem, planned.replay_budgets,
                    replay, options.proof, true, limits);
            } else {
                const auto eager = admit_eager_laned_witness_packing(
                    certified.circuit(), problem, planned.replay_budgets,
                    replay);
                if (eager.resources.eligible) {
                    limits.payload_execution_peak = {
                        eager.peak_live_scratch_bytes,
                        eager.peak_resident_bytes};
                }
                const auto options = laned_gkr_options(certified.circuit(), roots, planned);
                (void)admit_checkpoint_replay_server_storage(problem, planned.replay_budgets,
                    replay, options.proof, true, limits);
            }
            std::cout << "SETUP: exact replay and GKR memory preflight PASS before packing publication"
                      << std::endl;
        }
        std::error_code setup_space_error;
        const std::filesystem::space_info setup_space =
            std::filesystem::space(command.run_directory,
                                   setup_space_error);
        require(!setup_space_error,
                "failed to inspect host disk before packed setup");
        const SystemInfo setup_host = system_info();
        const std::uint64_t candidate_whole_setup_peak = checked_add(
            setup_host.peak_rss_bytes,
            setup_demand.remaining_setup_resident_reserve_bytes,
            "packed setup whole-process resident admission");
        constexpr std::uint64_t kMebibyte = 1ULL << 20U;
        std::cout
            << "SETUP: packed RAM preflight: observed prefix peak "
            << setup_host.peak_rss_bytes / kMebibyte
            << " MiB + remaining reserve "
            << setup_demand.remaining_setup_resident_reserve_bytes /
                   kMebibyte
            << " MiB = whole-setup envelope "
            << candidate_whole_setup_peak / kMebibyte
            << " MiB (profile cap "
            << capacity.max_resident_ram_bytes / kMebibyte << " MiB)\n"
            << std::flush;
        auto admitted_publication = admit_then_construct_packed_setup(
            setup_demand,
            {
                .max_live_disk_bytes = capacity.max_live_disk_bytes,
                .max_resident_ram_bytes =
                    capacity.max_resident_ram_bytes,
                .min_free_disk_bytes = capacity.min_free_disk_bytes,
                .host_available_disk_bytes = setup_space.available,
                .host_ram_bytes = setup_host.ram_bytes,
                .observed_prepublication_peak_rss_bytes =
                    setup_host.peak_rss_bytes,
            },
            [&] {
                activity.transition(
                    "publishing_external_role_preprocessing");
                return publish_packed_role_preprocessing<SealBackend>(
                    certified, specification, contexts.eval,
                    contexts.client, verifier,
                    {
                        .shared = command.run_directory / "shared" /
                                  "preprocessing" / "packed-shared",
                        .server = command.run_directory / "server" /
                                  "preprocessing" / "packed-server",
                        .client = command.run_directory / "client" /
                                  "preprocessing" / "packed-client",
                        .work = command.run_directory / "shared" /
                                "setup-work" / "packed",
                    },
                    publication_limits);
            });
        setup_prepublication_admission = admitted_publication.first;
        require(setup_prepublication_admission
                    .admitted_whole_setup_peak_resident_bytes ==
                    candidate_whole_setup_peak,
                "packed setup RAM preflight drifted during admission");
        root_storage_identity =
            admitted_publication.second.root.storage_identity;
        packing_setup_report =
            std::move(admitted_publication.second
                          .transcript_packing_report);
        packed_preprocessing_timing = packed_stopwatch.stop();
    }

    Stopwatch client_reopen_stopwatch;
    Digest reopened_client_workload_identity{};
    ProcessCodecPolicy codec;
    {
        activity.transition("independently_reopening_client_fhe_bundles");
        SealBackend::ClientContext reopened_client =
            SealBackend::deserialize_client_context_bundle(load_bundle(
                command.run_directory / "client" / "preprocessing" /
                    "client-context.bin",
                client_binding));
        SealBackend::PublicVerifierContext reopened_verifier =
            SealBackend::deserialize_public_verifier_context_bundle(
                load_bundle(command.run_directory / "client" /
                                "preprocessing" /
                                "public-verifier-context.bin",
                            verifier_binding),
                context_id,
                {
                    .max_bundle_bytes = checked_size(
                        verifier_binding.bytes, "verifier bundle"),
                    .max_poly_modulus_degree = profile.slots,
                    .max_rns_limbs = profile.fresh_rns_limbs() + 1U,
                });
        activity.transition("independently_reopening_client_packed_role");
        auto client = open_authenticated_packed_client_online_state<
            SealBackend>(
            command.run_directory / "shared" / "preprocessing" /
                "packed-shared",
            command.run_directory / "client" / "preprocessing" /
                "packed-client",
            root_storage_identity, std::move(reopened_client),
            std::move(reopened_verifier),
            opening_limits);
        reopened_client_workload_identity =
            client.workload().semantic_identity();
        require(reopened_client_workload_identity ==
                    certified.semantic_identity(),
                "independently reopened client workload disagrees with "
                "setup");
        codec = process_codec_policy(
            profile, certified.circuit(), client.verifier_setup(),
            *certified.public_setup().outsourced_gate_mle);
    }
    const Timing client_reopen_timing = client_reopen_stopwatch.stop();

    const std::uint64_t shared_persistent_bytes = regular_file_bytes(
        command.run_directory / "shared" / "preprocessing");
    const std::uint64_t server_private_persistent_bytes =
        regular_file_bytes(command.run_directory / "server" /
                           "preprocessing");
    const std::uint64_t client_private_persistent_bytes =
        regular_file_bytes(command.run_directory / "client" /
                           "preprocessing");
    require(client_private_persistent_bytes <=
                adaptive_storage_preflight
                    .conservative_client_private_persistent_bytes,
            "persisted client-private preprocessing exceeds its planner "
            "preflight reserve");
    capacity = process_capacity(host_budget);
    capacity.max_live_disk_bytes = reserve_role_private_disk(
        host_budget, client_private_persistent_bytes);

    ProcessSetupRecord record{
        .variant = command.variant_name,
        .profile = command.profile_name,
        .git_commit = LAMINATE_PACKED_CHECKPOINT_GIT_COMMIT,
        .build_type = LAMINATE_BUILD_TYPE,
        .seal_acceleration = LAMINATE_SEAL_ACCELERATION,
        .run_id = run_id,
        .root_storage_identity = root_storage_identity,
        .workload_semantic_identity = certified.semantic_identity(),
        .public_setup_digest = certified.setup_digest(),
        .circuit_digest = certified.circuit_digest(),
        .fhe_context_storage_id = context_id,
        .proof_ingress_policy = std::string(ingress.policy()),
        .proof_ingress_schedule_digest = ingress.digest(),
        .slots = profile.slots,
        .lanes = profile.lanes,
        .multiplicative_depth = profile.multiplicative_depth,
        .middle_width = profile.middle_width,
        .payload_operations = certified.payload().gates.size(),
        .input_ciphertexts = profile.input_ciphertexts,
        .output_ciphertexts = profile.output_ciphertexts,
        .packing_repetitions = profile.packing_repetitions,
        .selected_packing_repetitions =
            profile.selected_packing_repetitions,
        .basefold_queries = profile.basefold_queries,
        .selected_basefold_queries = profile.selected_basefold_queries,
        .basefold_log_rate = profile.basefold_log_rate,
        .ciphertext_commitment_policy_code =
            profile.ciphertext_commitment_policy.wire_code(),
        .data_prime_bit_sizes = profile.data_prime_bit_sizes,
        .special_prime_bits =
            static_cast<std::uint64_t>(profile.special_prime_bits),
        .data_primes = actual_data_primes,
        .special_prime = actual_special_prime,
        .fresh_modulus_product_bits = fresh_modulus_product_bits,
        .key_modulus_product_bits = key_modulus_product_bits,
        .diagnostic_stress_only =
            profile.is_reduced_security_stress_test(),
        .evaluation_bundle = evaluation_binding,
        .client_bundle = client_binding,
        .verifier_bundle = verifier_binding,
        .fixed_message_basis = fixed_basis_binding,
        .fixed_message_basis_artifact_id = fixed_basis_id,
        .fixed_message_basis_ntt_bytes = fixed_basis_ntt_bytes,
        .workload_max_bytes = publication_limits.storage.max_workload_bytes,
        .workload_decode =
            publication_limits.storage.workload_decode,
        .role_static_max_bytes =
            publication_limits.storage.max_role_artifact_bytes,
        .manifest_max_bytes = publication_limits.storage.max_manifest_bytes,
        .artifact_tree_files =
            publication_limits.storage.max_artifact_tree_files,
        .artifact_tree_directories =
            publication_limits.storage.max_artifact_tree_directories,
        .artifact_tree_file_max_bytes =
            publication_limits.storage.max_artifact_tree_file_bytes,
        .artifact_tree_total_bytes =
            publication_limits.storage.max_artifact_tree_bytes,
        .factored_tensor_count =
            publication_plan.transcript_packing.factored.tensors.size(),
        .evaluation_plan = evaluation,
        .replay_problem = problem,
        .capacity = capacity,
        .host_budget = host_budget,
        .client_private_persistent_bytes =
            client_private_persistent_bytes,
        .multiplication_scratch_bytes_by_reduction = scratch_caps,
        .request_wire_bytes = codec.request_wire_bytes,
        .response_wire_bytes = codec.response_wire_bytes,
        .ciphertext_wire_bytes = codec.ciphertext_wire_bytes,
        .request_max_ciphertexts = codec.request_max_ciphertexts,
        .response_max_ciphertexts = codec.response_max_ciphertexts,
        .proof_max_ciphertexts = codec.proof_max_ciphertexts,
        .proof_max_collection_elements =
            codec.proof_max_collection_elements,
        .proof_max_field_elements = codec.proof_max_field_elements,
        .proof_max_digests = codec.proof_max_digests,
        .gate_mle_retained_prover_key_bytes =
            gate_mle_resources.retained_prover_key_bytes,
        .gate_mle_opening_workspace_bytes =
            gate_mle_resources.opening_workspace_bytes,
        .gate_mle_retained_prover_key_disk_bytes =
            gate_mle_resources.retained_prover_key_disk_bytes,
        .gate_mle_opening_workspace_disk_bytes =
            gate_mle_resources.opening_workspace_disk_bytes,
        .gate_mle_affine_preparation_workspace_bytes =
            affine_gate_preparation_workspace_bytes(certified.circuit()),
        .packing_persistent_overlap_bytes =
            packing_setup_report.final_persistent_physical_bytes,
        .packing_peak_live_bytes =
            packing_setup_report.final_persistent_physical_bytes,
    };

    const std::uint64_t proving_key_bytes = checked_add(
        shared_persistent_bytes, server_private_persistent_bytes,
        "packed proving-key bytes");
    const std::uint64_t verifying_key_bytes = checked_add(
        shared_persistent_bytes, client_private_persistent_bytes,
        "packed verifying-key bytes");
    const std::uint64_t all_roles_persistent_bytes = checked_add(
        proving_key_bytes, client_private_persistent_bytes,
        "all-role setup persistent bytes");
    require(all_roles_persistent_bytes <=
                setup_prepublication_admission.final_persistent_bytes,
            "persisted packed setup exceeds its prepublication admission");
    const std::uint64_t persistent_server_bytes =
        packed_server_persistent_bytes(command, record);
    require(persistent_server_bytes == proving_key_bytes,
            "packed proving-key accounting disagrees with server "
            "preprocessing persistence");
    const std::uint64_t reserved_server_bytes =
        packed_server_reserved_bytes(record, persistent_server_bytes);
    const ProcessRamPolicy ram = process_ram_policy(record);
    require(ram.client_peak_bytes <=
                conservative_client_peak_resident_bytes,
            "exact packed client resident peak exceeds its planner "
            "preflight reserve");
    capacity = process_capacity(host_budget, client_private_persistent_bytes,
                                ram.client_peak_bytes);
    record.capacity = capacity;
    record.server_common_resident_bytes = ram.server_common_bytes;
    record.server_payload_gkr_only_resident_bytes =
        ram.server_payload_gkr_only_bytes;
    record.server_packing_only_resident_bytes =
        ram.server_packing_only_bytes;
    record.reduction_workspace_resident_bytes =
        ram.reduction_workspace_bytes;
    record.client_peak_resident_bytes = ram.client_peak_bytes;
    record.replay_budgets =
        replay_budgets(capacity, reserved_server_bytes, record);
    require_packed_server_reserve_binding(record,
                                          persistent_server_bytes);
    const PayloadCheckpointReplayPlan replay =
        plan_payload_checkpoint_replay(record.replay_problem,
                                       record.replay_budgets);
    if (profile.tier != PackedProcessTier::Quick) {
        require(
            replay.selected.replay_work_units == 0,
            "target qualification failed: actual disk/RAM capacity and "
            "reserves selected nonzero payload replay; do not start the "
            "expensive run");
    }
    require_packed_adaptive_storage_refinement(
        adaptive_storage_preflight, client_private_persistent_bytes,
        ram.client_peak_bytes, record.replay_budgets, replay);
    std::cout << "SETUP: payload replay work = "
              << replay.selected.replay_work_units
              << "; remaining admitted disk headroom = "
              << capacity.max_live_disk_bytes -
                     replay.selected.peak_live_scratch_bytes
              << " bytes" << std::endl;
    record.replay_plan_digest = replay_plan_digest(replay);

    PackedServerStaticRestore restored_server =
        restore_and_certify_packed_server_static(
            command, profile, record,
            [&](std::string_view stage) {
                activity.transition("independently_" +
                                    std::string(stage));
            }, execution.worker_threads);
    require(restored_server.server.workload().semantic_identity() ==
                reopened_client_workload_identity,
            "independently reopened role workloads disagree");
    auto setup_server = std::move(restored_server.server);
    const Timing persisted_roles_reopen_timing = add_timings(
        {client_reopen_timing, restored_server.load_preprocessing,
         restored_server.certify_replay_and_gkr_static});

    activity.transition("admitting_external_online_resources");
    Stopwatch admission_stopwatch;
    const std::filesystem::path admission_root =
        command.run_directory / "shared" / "setup-work" / "packed";
    CheckpointReplayServerStorageAdmission setup_storage_admission;
    {
        OneShotWorkTree admission_tree(admission_root);
        const OnlineRoots admission_roots = make_online_roots(
            admission_tree, certified.circuit(),
            checked_size(record.factored_tensor_count, "tensor count"));
        TranscriptPackingExternalAdmission packing_admission =
            admit_transcript_packing_external(
                packing_variant(profile.variant),
                setup_server.prover_setup().transcript_packing(),
                packing_online_options(admission_roots, record));
        const TranscriptPackingExternalPreflightReport packing_preflight =
            packing_admission.report();
        record.packing_preflight_digest =
            packing_preflight_digest(packing_preflight);
        record.packing_peak_live_bytes =
            packing_peak_live_bytes(packing_preflight);
        activity.transition(
            "preparing_authenticated_request_resources");
        PreparedPackedServerRequestResources prepared =
            prepare_authenticated_packed_server_request_resources(
                setup_server, profile, admission_roots, record,
                std::move(packing_admission));
        setup_storage_admission = prepared.storage_admission;
        admission_tree.require_empty();
        admission_tree.retire_success();
    }
    std::error_code admission_error;
    require(std::filesystem::is_empty(admission_root, admission_error) &&
                !admission_error,
            "setup admission did not retire its work directories");
    activity.transition("validating_online_resource_admission");
    require_host_capacity(command.run_directory, capacity,
                          setup_storage_admission,
                          persistent_server_bytes);
    require_concurrent_host_ram(setup_storage_admission, record);
    const Timing admission_timing = admission_stopwatch.stop();

    activity.transition("publishing_setup_record");
    const std::vector<std::uint8_t> setup_bytes = encode_setup(record);
    require(encode_setup(decode_setup(setup_bytes)) == setup_bytes,
            "setup record codec round trip failed");
    publish_private_file(command.run_directory / "shared" / "setup.bin",
                         setup_bytes);
    activity.transition("validating_persisted_setup_record");
    auto persisted_setup = timed([&] {
        return load_setup_record(command, profile);
    });
    require(encode_setup(persisted_setup.first) == setup_bytes,
            "persisted setup record differs from the admitted record");
    const Timing reopen_timing = add_timings(
        {persisted_roles_reopen_timing, persisted_setup.second});

    const SystemInfo final_setup_system = system_info();
    const std::uint64_t setup_resident_cap =
        host_budget.max_resident_ram_bytes;
    require(final_setup_system.peak_rss_bytes <=
                setup_prepublication_admission
                    .admitted_whole_setup_peak_resident_bytes &&
                final_setup_system.peak_rss_bytes <=
                    setup_resident_cap,
            "observed packed setup peak RSS " +
                std::to_string(final_setup_system.peak_rss_bytes) +
                " exceeds its admitted whole-setup envelope " +
                std::to_string(
                    setup_prepublication_admission
                        .admitted_whole_setup_peak_resident_bytes) +
                " or setup resident cap " +
                std::to_string(setup_resident_cap));
    const Timing total = total_stopwatch.stop();
    const std::int64_t setup_finished = unix_milliseconds();
    CompletedResultReport result(command.run_directory / "shared" /
                                 "setup-result.txt");
    const Record output(result.mirror());
    output.text("format", "laminate-packed-benchmark-setup-v1");
    emit_identity(output, command, record);
    emit_geometry(output, record);
    emit_gate_mle_parameters(output,
                             *certified.public_setup().outsourced_gate_mle);
    output.integer("security.basefold.pcs_rbr_bits", codec.basefold_rbr_bits);
    output.text("packing.r1cs.actual.classification",
                "exact-setup-bound-profile");
    output.text("parameters.gate_mle_profile",
                std::string(laminate::bench::gate_mle_strategy_name(
                    *certified.public_setup().outsourced_gate_mle)));
    output.integer(
        "parameters.gate_mle_tables",
        certified.public_setup().outsourced_gate_mle->tables.size());
    output.text(
        "parameters.gate_mle_server_state",
        "persisted-opening-state-reopened-at-server-startup");
    output.text("parameters.gate_mle_wire_bound",
                "setup-shaped-opening-bound");
    emit_packing_r1cs_geometry(output, "packing.r1cs.actual",
                               actual_r1cs);
    output.text("packing.r1cs.selected_target.classification",
                "formula-only-selected-target");
    output.integer("packing.r1cs.selected_target.depth",
                   selected_target.multiplicative_depth);
    output.integer("packing.r1cs.selected_target.middle_width",
                   selected_target.middle_width);
    output.integer("packing.r1cs.selected_target.payload_operations",
                   kBenchmarkPayloadOperationCount);
    emit_packing_r1cs_geometry(output,
                               "packing.r1cs.selected_target",
                               selected_target_r1cs);
    output.integer("timing.setup.started_unix_ms", setup_started);
    output.integer("timing.setup.finished_unix_ms", setup_finished);
    emit_exact_timing(output, "timing.setup.workload_compilation",
                      workload_timing);
    emit_exact_timing(output, "timing.setup.storage_preflight",
                      storage_preflight_timing);
    if (require_live_key_preflight) {
        output.text("noise_preflight.result", "PASS");
        output.text("noise_preflight.policy", "folded-target-pyramid-live-key-v1");
        output.text("noise_preflight.same_setup_key", "true");
        output.integer("noise_preflight.root_wire", 1042862);
        output.text("noise_preflight.outer_spartan_included", "false");
        // This is a component of workload_compilation, not an additional
        // top-level setup phase; do not double-count it in the total.
        emit_exact_timing(output, "timing.setup.live_key_noise_preflight",
                          live_key_preflight_timing);
    }
    emit_exact_timing(output, "timing.setup.fhe_preprocessing",
                      fhe_preprocessing_timing);
    emit_exact_timing(output, "timing.setup.packed_preprocessing",
                      packed_preprocessing_timing);
    emit_exact_timing(output, "timing.setup.verify_persisted",
                      reopen_timing);
    emit_exact_timing(output, "timing.setup.resource_admission",
                      admission_timing);
    emit_exact_timing(output, "timing.setup.total", total);
    output.integer("capacity.profile.max_live_disk_bytes",
                   capacity.max_live_disk_bytes);
    output.integer("capacity.profile.max_resident_ram_bytes",
                   capacity.max_resident_ram_bytes);
    output.integer("capacity.profile.min_free_disk_bytes",
                   capacity.min_free_disk_bytes);
    {
        const auto &preflight = adaptive_storage_preflight;
        const auto &selected = preflight.replay.selected;
        output.text("storage.planner_preflight.classification",
                    "exact-compiled-trace-formula-only");
        output.integer("storage.planner_preflight.gross_live_disk_bytes",
                       preflight.host_budget.max_live_disk_bytes);
        output.integer("storage.planner_preflight.max_live_disk_bytes",
                       preflight.replay_budgets.max_live_scratch_bytes);
        output.integer("storage.planner_preflight.min_free_disk_bytes",
                       kPackedAdaptiveMinFreeDiskBytes);
        output.integer(
            "storage.planner_preflight.client_private_persistent_reserve_bytes",
            preflight.conservative_client_private_persistent_bytes);
        output.integer(
            "storage.planner_preflight.server_common_reserve_bytes",
            kPackedAdaptiveServerCommonDiskReserveBytes);
        output.integer(
            "storage.planner_preflight.required_available_disk_bytes",
            preflight.required_available_disk_bytes);
        output.integer(
            "storage.planner_preflight.observed_available_disk_bytes",
            preflight.host_budget.observed_available_disk_bytes);
        output.integer(
            "memory.planner_preflight.observed_physical_ram_bytes",
            preflight.host_budget.observed_physical_ram_bytes);
        output.integer("memory.planner_preflight.safety_reserve_bytes",
                       kBenchmarkHostRamSafetyReserveBytes);
        output.integer("memory.planner_preflight.gross_resident_budget_bytes",
                       preflight.host_budget.max_resident_ram_bytes);
        output.integer(
            "memory.planner_preflight.client_peak_resident_reserve_bytes",
            preflight.conservative_client_peak_resident_bytes);
        output.integer("memory.planner_preflight.server_resident_cap_bytes",
                       preflight.replay_budgets
                           .max_resident_ciphertext_bytes);
        output.integer("storage.planner_preflight.selected_peak_live_bytes",
                       selected.peak_live_scratch_bytes);
        output.integer("storage.planner_preflight.selected_checkpoint_count",
                       selected.checkpoint_layers.size());
        output.integer("storage.planner_preflight.selected_checkpoint_bytes",
                       selected.checkpoint_bytes);
        output.integer("storage.planner_preflight.initial_forward_work_units",
                       selected.initial_forward_work_units);
        output.integer("storage.planner_preflight.repeated_work_units",
                       selected.replay_work_units);
        output.integer("storage.planner_preflight.cumulative_work_units",
                       selected.cumulative_work_units);
        output.real(
            "storage.planner_preflight.cumulative_recomputation_factor",
            static_cast<double>(selected.cumulative_work_units) /
                static_cast<double>(selected.initial_forward_work_units));
        output.integer(
            "storage.planner_preflight.maximum_recomputation_numerator",
            kPackedAdaptiveMaximumRecomputation.numerator);
        output.integer(
            "storage.planner_preflight.maximum_recomputation_denominator",
            kPackedAdaptiveMaximumRecomputation.denominator);
    }
    output.integer("storage.setup.server_persistent_bytes",
                   persistent_server_bytes);
    output.integer("storage.setup.shared_persistent_bytes",
                   shared_persistent_bytes);
    output.integer("storage.setup.server_private_persistent_bytes",
                   server_private_persistent_bytes);
    output.integer("storage.setup.client_private_persistent_bytes",
                   client_private_persistent_bytes);
    output.integer("storage.host_budget.gross_live_disk_bytes",
                   host_budget.max_live_disk_bytes);
    output.integer(
        "storage.host_budget.exact_client_private_persistent_bytes",
        client_private_persistent_bytes);
    output.integer("storage.host_budget.exact_server_live_disk_bytes",
                   capacity.max_live_disk_bytes);
    output.integer("memory.host_budget.gross_resident_budget_bytes",
                   host_budget.max_resident_ram_bytes);
    output.integer("memory.host_budget.operating_system_reserve_bytes",
                   kBenchmarkOperatingSystemRamReserveBytes);
    output.integer("memory.host_budget.page_cache_reserve_bytes",
                   kBenchmarkPageCacheRamReserveBytes);
    output.integer("memory.payload_storage.transfer_buffer_count", 3);
    output.integer("memory.payload_storage.transfer_buffer_bytes_each",
                   kFileTraceStoreTransferBufferBytes);
    output.integer("memory.payload_storage.transfer_buffer_reserve_bytes",
                   kPayloadStorageTransferResidentBytes);
    output.integer("memory.payload_storage.writeback_window_bytes", 0);
    output.text("storage.payload_storage.ephemeral_writeback_policy",
                "linux-submit-only-with-buffered-portable-fallback");
    output.integer(
        "storage.payload_storage.maximum_writeback_submission_bytes",
        kFileTraceStoreWritebackSubmissionBytes);
    output.integer("memory.payload_storage.sequential_reader_count", 2);
    output.integer("memory.payload_storage.prefetch_window_bytes_each",
                   kFileTraceStorePrefetchWindowBytes);
    output.integer("memory.payload_storage.prefetch_page_cache_budget_bytes",
                   2U * kFileTraceStorePrefetchWindowBytes);
    output.integer("storage.payload_storage.maximum_prefetch_request_bytes",
                   kFileTraceStorePrefetchRequestBytes);
    output.integer("memory.host_budget.exact_client_peak_resident_bytes",
                   record.client_peak_resident_bytes);
    output.integer("memory.host_budget.exact_server_resident_cap_bytes",
                   capacity.max_resident_ram_bytes);
    output.integer("storage.setup.proving_key_bytes", proving_key_bytes);
    output.integer("storage.setup.verifying_key_bytes",
                   verifying_key_bytes);
    output.integer("storage.setup.all_roles_persistent_bytes",
                   all_roles_persistent_bytes);
    output.integer("storage.setup.packing_persistent_bytes",
                   packing_setup_report.final_persistent_physical_bytes);
    // Keep the existing report field name; this credits both FHE bundles
    // and the GateMLE cache already present at the admission boundary.
    output.integer(
        "storage.setup.prepublication_fhe_persistent_bytes",
        setup_prepublication_admission
            .already_present_persistent_bytes);
    output.integer(
        "storage.setup.prepublication_admitted_persistent_bytes",
        setup_prepublication_admission.final_persistent_bytes);
    output.integer(
        "storage.setup.prepublication_admitted_peak_live_bytes",
        setup_prepublication_admission.peak_live_bytes);
    output.integer(
        "storage.setup.prepublication_additional_live_bytes",
        setup_prepublication_admission.additional_live_bytes);
    output.integer(
        "storage.setup.prepublication_required_available_bytes",
        setup_prepublication_admission.required_available_disk_bytes);
    output.integer(
        "storage.setup.prepublication_observed_available_bytes",
        setup_prepublication_admission.observed_available_disk_bytes);
    output.integer("storage.online.packing_peak_live_bytes",
                   record.packing_peak_live_bytes);
    output.text("storage.replay.selection_objective",
                "minimum-replay-work");
    {
        std::ostringstream layers;
        for (std::size_t index = 0;
             index < replay.selected.checkpoint_layers.size(); ++index) {
            if (index != 0) {
                layers << ',';
            }
            layers << replay.selected.checkpoint_layers[index];
        }
        output.text("storage.replay.selected_checkpoint_layers",
                    layers.str());
    }
    output.integer("storage.replay.used_nonpreferred_checkpoint",
                   replay.used_nonpreferred_checkpoint ? 1 : 0);
    output.integer("storage.replay.selected_checkpoint_bytes",
                   replay.selected.checkpoint_bytes);
    output.integer(
        "memory.replay.dense_multiplication_alias_cache_peak_resident_bytes",
        replay.selected
            .dense_multiplication_alias_cache_peak_resident_bytes);
    output.integer("storage.replay.persistent_reserve_bytes",
                   record.replay_budgets.reserved_live_scratch_bytes);
    output.integer(
        "storage.replay.maximum_consumer_artifact_bytes",
        replay.selected
            .post_replay_consumer_artifact_bytes_upper_bound);
    output.integer("storage.replay.admitted_peak_live_bytes",
                   replay.selected.peak_live_scratch_bytes);
    output.integer("memory.replay.admitted_peak_resident_bytes",
                   replay.selected.peak_resident_bytes);
    output.integer("storage.replay.remaining_headroom_bytes",
                   capacity.max_live_disk_bytes -
                       replay.selected.peak_live_scratch_bytes);
    output.integer("work.replay.initial_forward_units",
                   replay.selected.initial_forward_work_units);
    output.integer("work.replay.repeated_units",
                   replay.selected.replay_work_units);
    output.integer("work.replay.cumulative_units",
                   replay.selected.cumulative_work_units);
    output.real(
        "work.replay.cumulative_factor",
        static_cast<double>(replay.selected.cumulative_work_units) /
            static_cast<double>(
                replay.selected.initial_forward_work_units));
    output.integer("storage.server.admitted_peak_live_bytes",
                   setup_storage_admission.max_local_disk_bytes);
    output.integer("memory.server.admitted_peak_resident_bytes",
                   setup_storage_admission.max_resident_ram_bytes);
    output.integer("memory.server.common_resident_reserve_bytes",
                   record.server_common_resident_bytes);
    output.integer("memory.server.payload_gkr_only_resident_reserve_bytes",
                   record.server_payload_gkr_only_resident_bytes);
    output.integer("memory.server.packing_only_resident_reserve_bytes",
                   record.server_packing_only_resident_bytes);
    output.integer("memory.server.reduction_workspace_reserve_bytes",
                   record.reduction_workspace_resident_bytes);
    output.integer(
        "memory.server.multiplication_sort_buffer_limit_bytes",
        process_multiplication_sort_buffer_bytes(record));
    if (record.variant == "laned") {
        output.integer(
            "memory.server.laned_affine_max_chunks_per_batch",
            gkr::laned_detail::affine_detail::
                kLanedAffineChunksPerBatch);
        output.integer(
            "memory.server.laned_affine_peak_resident_ciphertexts",
            gkr::laned_detail::affine_detail::
                laned_affine_peak_resident_ciphertexts(
                    checked_size(record.slots / record.lanes,
                                 "reported Laned chunks")));
        output.integer(
            "memory.server.laned_affine_workspace_reserve_bytes",
            process_laned_affine_reduction_workspace_bytes(record));
    }
    output.integer(
        "memory.server.gate_mle_retained_prover_key_upper_bytes",
        record.gate_mle_retained_prover_key_bytes);
    output.integer(
        "memory.server.gate_mle_opening_workspace_upper_bytes",
        record.gate_mle_opening_workspace_bytes);
    output.integer("storage.server.gate_mle_retained_prover_key_upper_bytes",
                   record.gate_mle_retained_prover_key_disk_bytes);
    output.integer("storage.server.gate_mle_opening_workspace_upper_bytes",
                   record.gate_mle_opening_workspace_disk_bytes);
    output.integer("memory.server.affine_gate_preparation_workspace_upper_bytes",
                   record.gate_mle_affine_preparation_workspace_bytes);
    output.integer("memory.client.admitted_peak_resident_bytes",
                   record.client_peak_resident_bytes);
    output.integer("memory.concurrent.admitted_peak_resident_bytes",
                   checked_add(
                       setup_storage_admission.max_resident_ram_bytes,
                       record.client_peak_resident_bytes,
                       "reported concurrent resident peak"));
    output.integer(
        "memory.setup.prepublication_observed_peak_rss_bytes",
        setup_prepublication_admission
            .observed_prepublication_peak_rss_bytes);
    output.integer(
        "memory.setup.prepublication_remaining_resident_reserve_bytes",
        setup_prepublication_admission
            .remaining_setup_resident_reserve_bytes);
    output.integer(
        "memory.setup.prepublication_admitted_peak_resident_bytes",
        setup_prepublication_admission
            .admitted_whole_setup_peak_resident_bytes);
    output.integer("memory.setup.peak_rss_bytes",
                   final_setup_system.peak_rss_bytes);
    output.text("environment.command", exact_command(argc, argv));
    output.text("setup.result", "PASS");
    result.publish();
    activity.mark_complete();
    std::cout << "\nPACKED SETUP PASS\n";
    return 0;
}

void require_completed_setup(const ProcessCommand &command) {
    if (!result_contains(command.run_directory / "shared" /
                             "setup-result.txt",
                         "setup.result=PASS") ||
        !result_contains(command.run_directory / "shared" /
                             "setup-process-exit.txt",
                         "process.exit_status=0")) {
        throw std::runtime_error(
            "setup has not published PASS with a zero process exit");
    }
}

std::array<std::uint8_t, 64> fresh_nonce_entropy() {
    std::array<std::uint8_t, 64> result{};
    std::random_device source;
    for (std::uint8_t &byte : result) {
        byte = static_cast<std::uint8_t>(source());
    }
    return result;
}

FoldedWireDecodeLimits folded_wire_limits(
    const ProcessSetupRecord &record, bool response) {
    const std::size_t message = checked_size(
        response ? record.response_wire_bytes : record.request_wire_bytes,
        "wire cap");
    const std::size_t ciphertext =
        checked_size(record.ciphertext_wire_bytes, "ciphertext cap");
    const std::size_t ciphertexts = checked_size(
        response ? record.response_max_ciphertexts
                 : record.request_max_ciphertexts,
        "ciphertext count cap");
    return {
        .max_message_bytes = message,
        .max_ciphertexts = ciphertexts,
        .max_ciphertext_bytes = ciphertext,
        .max_total_ciphertext_bytes = checked_size(
            checked_multiply(ciphertexts, ciphertext,
                             "total ciphertext cap"),
            "total ciphertext cap"),
        .max_proof_bytes = response ? message : 0,
    };
}

LanedWireDecodeLimits laned_wire_limits(
    const ProcessSetupRecord &record, bool response) {
    const auto folded = folded_wire_limits(record, response);
    return {
        .max_message_bytes = folded.max_message_bytes,
        .max_ciphertexts = folded.max_ciphertexts,
        .max_ciphertext_bytes = folded.max_ciphertext_bytes,
        .max_total_ciphertext_bytes = folded.max_total_ciphertext_bytes,
        .max_proof_bytes = folded.max_proof_bytes,
    };
}

PackedProofDecodeLimits packed_proof_limits(
    const ProcessSetupRecord &record) {
    const std::size_t message =
        checked_size(record.response_wire_bytes, "proof cap");
    const std::size_t ciphertext =
        checked_size(record.ciphertext_wire_bytes, "ciphertext cap");
    return {
        .max_proof_bytes = message,
        .max_ciphertexts = checked_size(record.proof_max_ciphertexts,
                                        "proof ciphertext cap"),
        .max_ciphertext_bytes = ciphertext,
        .max_total_ciphertext_bytes = checked_size(
            checked_multiply(record.proof_max_ciphertexts,
                             record.ciphertext_wire_bytes,
                             "proof ciphertext bytes"),
            "proof ciphertext bytes"),
        .max_collection_elements = checked_size(
            record.proof_max_collection_elements,
            "proof collection cap"),
        .max_total_field_elements = checked_size(
            record.proof_max_field_elements, "proof field cap"),
        .max_total_digests = checked_size(
            record.proof_max_digests, "proof digest cap"),
    };
}

void emit_verifier_timings(const Record &record,
                           const protocol::BaseVerifierTimings &timings) {
    emit_exact_timing(
        record, "timing.client.verify.transcript_packing",
        {timings.packed_message_verification_wall_ms,
         timings.packed_message_verification_cpu_ms});
    emit_exact_timing(
        record, "timing.client.verify.gate_mle_opening",
        {timings.gate_mle_opening_wall_ms,
         timings.gate_mle_opening_cpu_ms});
    record.integer("timing.client.verify.layer_count",
                   timings.layers.size());
    for (std::size_t index = 0; index < timings.layers.size(); ++index) {
        const auto &layer = timings.layers[index];
        const std::string prefix =
            "timing.client.verify.layer." + std::to_string(index);
        record.integer(prefix + ".circuit_layer", layer.layer);
        record.text(prefix + ".kind",
                    layer.kind == LayerKind::Affine
                        ? "affine"
                        : layer.kind == LayerKind::Multiplication
                              ? "multiplication"
                              : "input");
        emit_exact_timing(record, prefix,
                          {layer.wall_ms, layer.cpu_ms});
    }
}

/// Client verification returns only an optional output vector. Track the
/// transcript-packing boundaries alongside the persistent progress journal so
/// an honest rejection can still be attributed to the phase that rejected it.
struct PackedClientVerificationProgress {
    bool verifier_statement_started = false;
    bool verifier_statement_completed = false;
    bool spartan_verify_started = false;
    bool spartan_verify_completed = false;
    bool threshold_checks_started = false;
    bool threshold_checks_completed = false;
    bool unpack_started = false;
    bool unpack_completed = false;

    void observe(const RuntimeProgressEvent &event) noexcept {
        const bool completed =
            event.boundary == RuntimeProgressBoundary::End;
        if (event.stage ==
            RuntimeProgressStage::TranscriptPackingVerifierStatement) {
            verifier_statement_started = true;
            verifier_statement_completed =
                verifier_statement_completed || completed;
        } else if (event.stage ==
                   RuntimeProgressStage::TranscriptPackingSpartanVerify) {
            spartan_verify_started = true;
            spartan_verify_completed =
                spartan_verify_completed || completed;
        } else if (event.stage ==
            RuntimeProgressStage::TranscriptPackingThresholdChecks) {
            threshold_checks_started = true;
            threshold_checks_completed =
                threshold_checks_completed || completed;
        } else if (event.stage ==
                   RuntimeProgressStage::TranscriptPackingUnpack) {
            unpack_started = true;
            unpack_completed = unpack_completed || completed;
        }
    }
};

RuntimeProgressCallback tracked_client_verification_progress(
    ProtocolProgressJournal &journal,
    PackedClientVerificationProgress &observed) {
    RuntimeProgressCallback persistent = journal.callback();
    return [persistent = std::move(persistent), &observed](
               const RuntimeProgressEvent &event) noexcept {
        // Persistent diagnostic logging is outside client computation.
        verification_profile::ScopedVerificationPause pause;
        observed.observe(event);
        persistent(event);
    };
}

std::string threshold_rejection_message(
    std::string_view variant,
    const LazyTernaryThresholdAssessment &assessment) {
    std::ostringstream message;
    message << variant
            << " transcript-packing threshold rejected: configured "
               "threshold="
            << assessment.configured_threshold
            << "; maximum observed norm="
            << assessment.maximum_observed_norm
            << "; failing reveals=" << assessment.failing_reveal_count
            << "; checked reveals=" << assessment.checked_reveal_count
            << "; observed reveals=" << assessment.observed_reveal_count
            << "; expected reveals=" << assessment.expected_reveal_count
            << "; first failing reveal (one-based)=";
    if (assessment.first_failing_reveal_index) {
        message << (*assessment.first_failing_reveal_index + 1U)
                << " of " << assessment.checked_reveal_count;
    } else {
        message << "none";
    }
    return message.str();
}

std::string packed_client_verification_rejection(
    std::string_view variant, std::optional<std::size_t> output_count,
    std::size_t expected_output_count,
    const LazyTernaryThresholdAssessment &assessment,
    const PackedClientVerificationProgress &progress) {
    if (output_count) {
        return std::string(variant) + " verifier returned " +
               std::to_string(*output_count) +
               " payload outputs; setup requires " +
               std::to_string(expected_output_count);
    }
    if (!progress.verifier_statement_started) {
        return std::string(variant) +
               " verification rejected before transcript packing began "
               "(response binding, setup, structure, or output-claim "
               "validation)";
    }
    if (!progress.verifier_statement_completed) {
        return std::string(variant) +
               " transcript-packing verifier-statement construction did "
               "not complete";
    }
    if (!progress.spartan_verify_started ||
        !progress.spartan_verify_completed) {
        return std::string(variant) +
               " transcript-packing Spartan verification did not complete";
    }
    if (!progress.threshold_checks_started) {
        return std::string(variant) +
               " transcript-packing Spartan proof rejected";
    }
    if (!progress.threshold_checks_completed) {
        return std::string(variant) +
               " transcript-packing threshold checks did not complete";
    }
    if (!assessment.checks_performed) {
        return std::string(variant) +
               " transcript-packing threshold rejected a malformed reveal "
               "count: observed=" +
               std::to_string(assessment.observed_reveal_count) +
               "; expected=" +
               std::to_string(assessment.expected_reveal_count);
    }
    if (!assessment.accepts()) {
        return threshold_rejection_message(variant, assessment);
    }
    if (!progress.unpack_completed) {
        return std::string(variant) +
               (progress.unpack_started
                    ? " transcript unpacking failed after threshold acceptance"
                    : " transcript unpacking did not begin after threshold acceptance");
    }
    return std::string(variant) +
           " post-unpack GKR or GateMLE verification rejected";
}

template <typename Breakdown>
void emit_packed_proof_sizes(const Record &record,
                             std::size_t response_bytes,
                             const Breakdown &proof) {
    record.integer("proof.response.total_bytes", response_bytes);
    record.integer("proof.canonical.total_bytes", proof.total_bytes);
    record.integer("proof.canonical.statement_and_metadata_bytes",
                   proof.statement_and_metadata_bytes);
    record.integer("proof.canonical.committed_gkr_bytes",
                   proof.committed_gkr_bytes);
    record.integer("proof.canonical.well_formedness_reveal_bytes",
                   proof.well_formedness_reveal_bytes);
    record.integer("proof.canonical.digit_packing_ciphertext_bytes",
                   proof.digit_packing_ciphertext_bytes);
    record.integer("proof.canonical.spartan_packing_proof_bytes",
                   proof.spartan_packing_proof_bytes);
    record.integer("proof.committed_gkr.commitment_digest_bytes",
                   proof.gkr_commitment_bytes);
    record.integer("proof.committed_gkr.gate_mle_opening_bytes",
                   proof.gate_mle_opening_bytes);
    record.integer("proof.logical_round_messages",
                   proof.logical_round_messages);
    record.integer("proof.extension_ciphertexts",
                   proof.extension_ciphertexts);
    record.integer("proof.base_ciphertexts", proof.base_ciphertexts);
    record.integer("proof.public_plaintext_coefficients",
                   proof.public_plaintext_coefficients);
    record.integer("proof.public_plaintext_field_elements",
                   proof.public_plaintext_field_elements);
}

template <typename GkrReport>
std::uint64_t peak_gkr_scratch_bytes(const GkrReport &report) {
    std::uint64_t peak = 0;
    for (const auto &reduction : report.reductions) {
        if (!reduction.multiplication_artifact) {
            continue;
        }
        const auto &artifact = *reduction.multiplication_artifact;
        if constexpr (requires { artifact.storage; artifact.build; }) {
            peak = std::max(
                peak,
                std::max(
                    artifact.storage.physical_bytes,
                    artifact.build
                        .external_sort_peak_combined_artifact_bytes));
        } else {
            peak = std::max(
                peak,
                std::max(
                    artifact.report.physical_bytes,
                    artifact.statistics
                        .external_sort_peak_combined_artifact_bytes));
        }
    }
    return peak;
}

struct GkrSortDiagnostics {
    std::uint64_t artifacts = 0;
    std::uint64_t initial_runs = 0;
    std::uint64_t runs_created = 0;
    std::uint64_t merge_passes = 0;
    std::uint64_t maximum_open_runs = 0;
    std::uint64_t temporary_bytes_written = 0;
    std::uint64_t peak_buffered_payload_bytes = 0;
    std::uint64_t retained_temporary_bytes = 0;
};

template <typename GkrReport>
GkrSortDiagnostics gkr_sort_diagnostics(const GkrReport &report) {
    GkrSortDiagnostics result;
    for (const auto &reduction : report.reductions) {
        if (!reduction.multiplication_artifact) {
            continue;
        }
        const auto &artifact = *reduction.multiplication_artifact;
        const auto &statistics = [&]() -> const auto & {
            if constexpr (requires { artifact.build; }) {
                return artifact.build;
            } else {
                return artifact.statistics;
            }
        }();
        ++result.artifacts;
        result.initial_runs = checked_add(
            result.initial_runs, statistics.external_sort_initial_runs,
            "GKR external-sort initial runs");
        result.runs_created = checked_add(
            result.runs_created, statistics.external_sort_runs_created,
            "GKR external-sort runs created");
        result.merge_passes = checked_add(
            result.merge_passes, statistics.external_sort_merge_passes,
            "GKR external-sort merge passes");
        result.maximum_open_runs = std::max<std::uint64_t>(
            result.maximum_open_runs,
            statistics.external_sort_maximum_open_runs);
        result.temporary_bytes_written = checked_add(
            result.temporary_bytes_written,
            statistics.external_sort_temporary_bytes_written,
            "GKR external-sort temporary bytes");
        result.peak_buffered_payload_bytes = std::max(
            result.peak_buffered_payload_bytes,
            statistics.external_sort_peak_buffered_payload_bytes);
        result.retained_temporary_bytes = checked_add(
            result.retained_temporary_bytes,
            statistics.external_sort_retained_temporary_bytes,
            "GKR retained external-sort bytes");
    }
    return result;
}

void emit_packing_storage(
    const Record &record,
    const TranscriptPackingExternalProverReport &report) {
    record.integer(
        "storage.packing.outer_assignment_physical_bytes",
        report.prefix_storage.outer_assignment_physical_bytes);
    record.integer("storage.packing.spartan_peak_live_bytes",
                   report.storage.peak_live_storage_bytes);
    record.integer("storage.packing.preprocessing_validation_bytes",
                   report.storage.preprocessing_validation_bytes);
    record.integer("storage.packing.persistent_input_physical_bytes",
                   report.storage.persistent_input_physical_bytes);
}

void emit_replay_source_io(
    const Record &record, std::string_view phase,
    const PayloadCheckpointReplayIoReport &report) {
    const std::string prefix =
        "work.replay." + std::string(phase) + ".";
    record.text(prefix + "storage.artifact_integrity",
                "same-process-inode-bound-nonreopenable");
    const auto timing = [&](std::string_view name,
                            const FileTraceStoreOperationTiming &value) {
        record.real(prefix + "timing." + std::string(name) + ".wall_ms",
                    value.wall_ms);
        record.real(prefix + "timing." + std::string(name) + ".cpu_ms",
                    value.cpu_ms);
    };
    timing("relation", report.relation);
    timing("deserialization", report.deserialization);
    timing("fhe", report.fhe_evaluation);
    timing("modulus_switch", report.modulus_switching);
    timing("serialization", report.storage_writes.serialization);
    timing("buffer_assembly", report.storage_writes.buffer_assembly);
    timing("hashing", report.storage_writes.hashing);
    timing("capacity_admission",
           report.storage_writes.capacity_admission);
    timing("output_submission",
           report.storage_writes.output_submission);
    timing("storage_write", report.storage_writes.storage_write);
    timing("writeback_submission",
           report.storage_writes.writeback_submission);
    timing("writeback_wait", report.storage_writes.writeback_wait);
    timing("drain_close_publication",
           report.storage_writes.drain_close_and_publication);
    timing("storage_read", report.storage_reads.storage_read);
    timing("prefetch", report.storage_reads.prefetch);
    record.integer(prefix + "storage.capacity_probes",
                   report.storage_writes.capacity_probes);
    record.integer(prefix + "storage.write_batches",
                   report.storage_writes.write_batches);
    record.integer(prefix + "storage.write_syscalls",
                   report.storage_writes.write_syscalls);
    record.integer(prefix + "storage.application_write_bytes",
                   report.storage_writes.bytes_submitted);
    record.integer(prefix + "storage.authenticated_records",
                   report.storage_writes.authenticated_records);
    record.integer(prefix + "storage.authenticated_record_bytes",
                   report.storage_writes.authenticated_record_bytes);
    record.integer(prefix + "storage.same_process_unhashed_records",
                   report.storage_writes.same_process_unhashed_records);
    record.integer(prefix + "storage.same_process_unhashed_record_bytes",
                   report.storage_writes.same_process_unhashed_record_bytes);
    record.integer(prefix + "storage.record_copy_bytes",
                   report.storage_writes.record_copy_bytes);
    record.integer(prefix + "storage.maximum_write_batch_bytes",
                   report.storage_writes.maximum_batch_bytes);
    record.integer(prefix + "storage.write_transfer_buffer_bytes",
                   report.storage_writes.transfer_buffer_bytes);
    record.integer(prefix + "storage.write_transfer_buffer_count",
                   report.storage_writes.transfer_buffer_count);
    record.integer(prefix + "storage.writeback_files_enabled",
                   report.storage_writes.writeback_files_enabled);
    record.integer(prefix + "storage.writeback_files_fallback",
                   report.storage_writes.writeback_files_fallback);
    record.integer(prefix + "storage.writeback_files_submit_only",
                   report.storage_writes.writeback_files_submit_only);
    record.integer(prefix + "storage.writeback_submission_attempts",
                   report.storage_writes.writeback_submission_attempts);
    record.integer(prefix + "storage.writeback_submission_successes",
                   report.storage_writes.writeback_submission_successes);
    record.integer(prefix + "storage.writeback_wait_attempts",
                   report.storage_writes.writeback_wait_attempts);
    record.integer(prefix + "storage.writeback_wait_successes",
                   report.storage_writes.writeback_wait_successes);
    record.integer(prefix + "storage.writeback_range_bytes_submitted",
                   report.storage_writes.writeback_range_bytes_submitted);
    record.integer(prefix + "storage.writeback_range_bytes_waited",
                   report.storage_writes.writeback_range_bytes_waited);
    record.integer(prefix + "storage.maximum_writeback_submission_bytes",
                   report.storage_writes.maximum_writeback_submission_bytes);
    record.integer(prefix + "storage.writeback_window_bytes",
                   report.storage_writes.writeback_window_bytes);
    record.integer(prefix + "storage.maximum_unwaited_writeback_range_bytes",
                   report.storage_writes.maximum_unwaited_writeback_range_bytes);
    record.integer(prefix + "storage.writeback_drains",
                   report.storage_writes.writeback_drains);
    record.integer(prefix + "storage.writeback_drain_range_bytes",
                   report.storage_writes.writeback_drain_range_bytes);
    record.integer(prefix + "storage.writeback_drains_skipped",
                   report.storage_writes.writeback_drains_skipped);
    record.integer(prefix + "storage.writeback_range_bytes_without_explicit_wait",
                   report.storage_writes.writeback_range_bytes_without_explicit_wait);
    record.integer(prefix + "storage.positional_write_calls",
                   report.storage_writes.positional_write_calls);
    record.integer(prefix + "storage.positional_write_bytes",
                   report.storage_writes.positional_write_bytes);
    record.integer(prefix + "storage.read_batches",
                   report.storage_reads.read_batches);
    record.integer(prefix + "storage.read_syscalls",
                   report.storage_reads.read_syscalls);
    record.integer(prefix + "storage.application_read_bytes",
                   report.storage_reads.bytes_transferred);
    record.integer(prefix + "storage.prefetch_requests",
                   report.storage_reads.prefetch_requests);
    record.integer(prefix + "storage.prefetch_bytes_requested",
                   report.storage_reads.prefetch_bytes_requested);
    record.integer(prefix + "storage.prefetch_fallbacks",
                   report.storage_reads.prefetch_fallbacks);
    record.integer(prefix + "storage.prefetch_seek_disables",
                   report.storage_reads.prefetch_seek_disables);
    record.integer(prefix + "storage.prefetch_window_bytes",
                   report.storage_reads.prefetch_window_bytes);
    record.integer(prefix + "storage.maximum_prefetch_request_bytes",
                   report.storage_reads.maximum_prefetch_request_bytes);
    record.integer(prefix + "storage.maximum_read_batch_bytes",
                   report.storage_reads.maximum_batch_bytes);
    record.integer(prefix + "storage.read_transfer_buffer_bytes",
                   report.storage_reads.transfer_buffer_bytes);
    record.integer(prefix + "monotone_relations",
                   report.monotone_dense_multiplication_relations);
    record.integer(
        prefix + "monotone_range_readers",
        report.monotone_dense_multiplication_range_readers_opened);
    record.integer(
        prefix + "monotone_source_records",
        report.monotone_dense_multiplication_source_records_read);
    record.integer(prefix + "alias_cached_relations",
                   report.alias_cached_dense_multiplication_relations);
    record.integer(
        prefix + "alias_cache_range_readers",
        report.alias_cached_dense_multiplication_range_readers_opened);
    record.integer(
        prefix + "alias_cache_distinct_source_records",
        report
            .alias_cached_dense_multiplication_distinct_source_records_read);
    record.integer(
        prefix + "alias_cache_logical_source_uses",
        report.alias_cached_dense_multiplication_logical_source_uses);
    record.integer(
        prefix + "alias_cache_generic_source_records",
        report.alias_cached_dense_multiplication_fallback_source_records);
    record.integer(prefix + "identity_affine_alias_relations",
                   report.identity_affine_alias_relations);
    record.integer(prefix + "identity_affine_alias_fallbacks",
                   report.identity_affine_alias_fallbacks);
    record.integer(prefix + "identity_affine_alias_records_reused",
                   report.identity_affine_alias_records_reused);
    record.integer(prefix + "identity_affine_alias_layer_bytes_reused",
                   report.identity_affine_alias_layer_bytes_reused);
    record.integer(prefix + "identity_affine_alias_unique_bytes_written",
                   report.identity_affine_alias_unique_bytes_written);
}

int run_server(const ProcessCommand &command, int argc, char **argv) {
    Stopwatch process_stopwatch;
    const std::int64_t process_started = unix_milliseconds();
    const PackedProcessProfile profile =
        packed_process_profile(command.variant, command.tier,
                               command.lanes);
    require_profile_execution_policy_before_artifacts(profile);
    require_completed_setup(command);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "server" /
                              "activity.jsonl",
                          "server");
    ProtocolProgressJournal progress(command.run_directory / "server" /
                                     "progress.jsonl");
    activity.transition("loading_setup_record");
    progress.phase("server.loading_setup_record");
    auto loaded_record = timed([&] {
        return load_setup_record(command, profile);
    });
    ProcessSetupRecord record = std::move(loaded_record.first);
    PackedServerStaticRestore restored_server =
        restore_and_certify_packed_server_static(
            command, profile, record,
            [&](std::string_view stage) {
                activity.transition(stage);
                progress.phase("server." + std::string(stage));
            });
    auto server = std::move(restored_server.server);
    const CertifiedPackedWorkloadStatic &workload = server.workload();
    const Timing load_timing = add_timings(
        {loaded_record.second, restored_server.load_preprocessing});
    const Timing static_planning_timing =
        restored_server.certify_replay_and_gkr_static;

    activity.transition("deriving_persistent_reserve");
    progress.phase("server.deriving_persistent_reserve");
    Stopwatch persistent_reserve_stopwatch;
    const std::uint64_t persistent_server_bytes =
        packed_server_persistent_bytes(command, record);
    require_packed_server_reserve_binding(record,
                                          persistent_server_bytes);
    const Timing persistent_reserve_timing =
        persistent_reserve_stopwatch.stop();

    const std::filesystem::path work_root =
        command.run_directory / "server" / "work";
    activity.transition("creating_request_work_tree");
    progress.phase("server.creating_request_work_tree");
    Stopwatch resource_roots_stopwatch;
    OneShotWorkTree work_tree(work_root);
    const OnlineRoots roots = make_online_roots(
        work_tree, workload.circuit(),
        checked_size(record.factored_tensor_count, "tensor count"));
    const Timing resource_roots_timing = resource_roots_stopwatch.stop();

    activity.transition("admitting_transcript_packing");
    progress.phase("server.admitting_transcript_packing");
    Stopwatch admission_stopwatch;
    TranscriptPackingExternalAdmission packing_admission =
        admit_transcript_packing_external(
            packing_variant(profile.variant),
            server.prover_setup().transcript_packing(),
            packing_online_options(roots, record));
    const TranscriptPackingExternalPreflightReport packing_preflight =
        packing_admission.report();
    require(packing_preflight_digest(packing_preflight) ==
                    record.packing_preflight_digest &&
                packing_peak_live_bytes(packing_preflight) ==
                    record.packing_peak_live_bytes,
            "server transcript-packing admission differs from setup");
    const Timing admission_timing = admission_stopwatch.stop();

    activity.transition("preparing_authenticated_request_resources");
    progress.phase("server.preparing_authenticated_request_resources");
    Stopwatch checkpoint_admission_stopwatch;
    PreparedPackedServerRequestResources prepared_resources =
        prepare_authenticated_packed_server_request_resources(
            server, profile, roots, record, std::move(packing_admission),
            progress.callback());
    const CheckpointReplayServerStorageAdmission startup_storage_admission =
        prepared_resources.storage_admission;
    require_host_capacity(command.run_directory, record.capacity,
                          startup_storage_admission,
                          persistent_server_bytes);
    require_concurrent_host_ram(startup_storage_admission, record);
    const Timing checkpoint_admission_timing =
        checkpoint_admission_stopwatch.stop();
    const Timing startup_timing = add_timings(
        {load_timing, static_planning_timing,
         persistent_reserve_timing});
    const Timing recurring_pre_request_timing = add_timings(
        {resource_roots_timing, admission_timing,
         checkpoint_admission_timing});

    const std::filesystem::path request_path =
        command.run_directory / "shared" / "transcript" /
        "cli-to-srv-request.bin";
    const std::filesystem::path response_path =
        command.run_directory / "shared" / "transcript" /
        "srv-to-cli-response.bin";
    const Timing wait_timing = wait_for_artifact(
        request_path, "server", "client request", activity,
        "waiting_for_client_request",
        command.run_directory / "client" / "failure.txt",
        command.run_directory / "client" / "activity.jsonl");
    const std::int64_t request_observed = unix_milliseconds();

    activity.transition("reading_request");
    auto request_file = timed([&] {
        return read_bounded_file(request_path, record.request_wire_bytes);
    });
    const std::size_t request_bytes_count = request_file.first.size();
    const Timing request_capacity_timing = timed_void([&] {
        require_host_capacity(command.run_directory, record.capacity,
                              startup_storage_admission,
                              persistent_server_bytes,
                              request_bytes_count);
    });
    Timing decode_timing;
    Timing evaluation_timing;
    Timing proof_timing;
    Timing proof_validation_timing;
    Timing gkr_timing;
    Timing transcript_packing_timing;
    Timing encode_timing;
    Timing finalize_timing;
    Timing publish_timing;
    std::size_t response_bytes_count = 0;
    std::uint64_t gkr_peak_scratch = 0;
    GkrSortDiagnostics gkr_sort;
    PayloadCheckpointReplayExecutionReport replay_report;
    TranscriptPackingExternalProverReport packing_report;
    CheckpointReplayServerStorageAdmission final_storage_admission;
    std::vector<std::uint8_t> response_bytes;
    std::optional<protocol::FoldedProofSizeBreakdown> folded_proof_size;
    std::optional<protocol::LanedProofSizeBreakdown> laned_proof_size;
    SealBackend::OperationCounts evaluation_counts;
    SealBackend::OperationCounts proving_counts;

    Transcript transcript(kProcessTranscriptDomain);

    if (profile.variant == PackedProcessVariant::Folded) {
        activity.transition("decoding_request");
        auto decoded = timed([&] {
            auto request = decode_folded_evaluation_request<SealBackend>(
                server.evaluation_context(), request_file.first,
                folded_wire_limits(record, false));
            std::vector<std::uint8_t>().swap(request_file.first);
            return request;
        });
        decode_timing = decoded.second;
        FoldedEvaluationRequest<SealBackend> request =
            std::move(decoded.first);

        activity.transition("payload_evaluation");
        progress.phase("server.payload_evaluation");
        SealBackend::reset_counts(server.evaluation_context());
        SealBackend::set_counting(server.evaluation_context(), true);
        auto evaluated = timed([&] {
            auto result =
                evaluate_folded_request<
                    SealBackend>(server, request,
                                 std::move(*prepared_resources.folded));
            request = FoldedEvaluationRequest<SealBackend>{};
            return result;
        });
        SealBackend::set_counting(server.evaluation_context(), false);
        evaluation_counts = SealBackend::counts(server.evaluation_context());
        evaluation_timing = evaluated.second;

        activity.transition("proving");
        progress.phase("server.proving");
        SealBackend::reset_counts(server.evaluation_context());
        SealBackend::set_counting(server.evaluation_context(), true);
        auto proved = timed([&] {
            return prove_folded_response_irreversible<
                SealBackend>(server, evaluated.first, transcript);
        });
        SealBackend::set_counting(server.evaluation_context(), false);
        proving_counts = SealBackend::counts(server.evaluation_context());
        proof_timing = proved.second;
        proof_validation_timing = timed_void([&] {
            require(proved.first.payload_replay_report
                            .all_payload_artifacts_retired &&
                        proved.first.payload_replay_report
                                .live_physical_bytes == 0 &&
                        proved.first.transcript_packing_report
                                .prefix_storage ==
                            packing_preflight.prefix_storage &&
                        proved.first.transcript_packing_report.storage ==
                            packing_preflight.spartan_storage &&
                        proved.first.storage_admission ==
                            startup_storage_admission,
                    "folded proof resource retirement/admission mismatch");
            gkr_peak_scratch =
                peak_gkr_scratch_bytes(proved.first.gkr_report);
            gkr_sort = gkr_sort_diagnostics(proved.first.gkr_report);
            replay_report = proved.first.payload_replay_report;
            packing_report = proved.first.transcript_packing_report;
            gkr_timing = {
                proved.first.phase_timings.gkr_wall_ms,
                proved.first.phase_timings.gkr_cpu_ms};
            transcript_packing_timing = {
                proved.first.phase_timings.transcript_packing_wall_ms,
                proved.first.phase_timings.transcript_packing_cpu_ms};
            final_storage_admission = proved.first.storage_admission;
        });
        activity.transition("encoding_response");
        auto encoded = timed([&] {
            auto result = encode_folded_response_with_size<SealBackend>(
                server.evaluation_context(), proved.first.response,
                checked_size(record.response_wire_bytes,
                             "response cap"));
            proved.first.response = FoldedResponse<SealBackend>{};
            return result;
        });
        encode_timing = encoded.second;
        folded_proof_size = std::move(encoded.first.proof_size);
        response_bytes = std::move(encoded.first.bytes);
    } else {
        activity.transition("decoding_request");
        auto decoded = timed([&] {
            auto request = decode_laned_evaluation_request<SealBackend>(
                server.evaluation_context(), request_file.first,
                laned_wire_limits(record, false));
            std::vector<std::uint8_t>().swap(request_file.first);
            return request;
        });
        decode_timing = decoded.second;
        LanedEvaluationRequest<SealBackend> request =
            std::move(decoded.first);

        activity.transition("payload_evaluation");
        progress.phase("server.payload_evaluation");
        SealBackend::reset_counts(server.evaluation_context());
        SealBackend::set_counting(server.evaluation_context(), true);
        auto evaluated = timed([&] {
            auto result =
                evaluate_laned_request<
                    SealBackend>(server, request,
                                 std::move(*prepared_resources.laned));
            request = LanedEvaluationRequest<SealBackend>{};
            return result;
        });
        SealBackend::set_counting(server.evaluation_context(), false);
        evaluation_counts = SealBackend::counts(server.evaluation_context());
        evaluation_timing = evaluated.second;

        activity.transition("proving");
        progress.phase("server.proving");
        SealBackend::reset_counts(server.evaluation_context());
        SealBackend::set_counting(server.evaluation_context(), true);
        auto proved = timed([&] {
            return prove_laned_response_irreversible<
                SealBackend>(server, evaluated.first, transcript);
        });
        SealBackend::set_counting(server.evaluation_context(), false);
        proving_counts = SealBackend::counts(server.evaluation_context());
        proof_timing = proved.second;
        proof_validation_timing = timed_void([&] {
            require(proved.first.payload_replay_report
                            .all_payload_artifacts_retired &&
                        proved.first.payload_replay_report
                                .live_physical_bytes == 0 &&
                        proved.first.transcript_packing_report
                                .prefix_storage ==
                            packing_preflight.prefix_storage &&
                        proved.first.transcript_packing_report.storage ==
                            packing_preflight.spartan_storage &&
                        proved.first.storage_admission ==
                            startup_storage_admission,
                    "laned proof resource retirement/admission mismatch");
            gkr_peak_scratch =
                peak_gkr_scratch_bytes(proved.first.gkr_report);
            gkr_sort = gkr_sort_diagnostics(proved.first.gkr_report);
            replay_report = proved.first.payload_replay_report;
            packing_report = proved.first.transcript_packing_report;
            gkr_timing = {
                proved.first.phase_timings.gkr_wall_ms,
                proved.first.phase_timings.gkr_cpu_ms};
            transcript_packing_timing = {
                proved.first.phase_timings.transcript_packing_wall_ms,
                proved.first.phase_timings.transcript_packing_cpu_ms};
            final_storage_admission = proved.first.storage_admission;
        });
        activity.transition("encoding_response");
        auto encoded = timed([&] {
            auto result = encode_laned_response_with_size<SealBackend>(
                server.evaluation_context(), proved.first.response,
                checked_size(record.response_wire_bytes,
                             "response cap"));
            proved.first.response = LanedResponse<SealBackend>{};
            return result;
        });
        encode_timing = encoded.second;
        laned_proof_size = std::move(encoded.first.proof_size);
        response_bytes = std::move(encoded.first.bytes);
    }

    finalize_timing = timed_void([&] {
        require(response_bytes.size() <= record.response_wire_bytes,
                "encoded response exceeds setup-derived wire cap");
        response_bytes_count = response_bytes.size();
        work_tree.retire_success();
        std::error_code work_error;
        require(std::filesystem::is_empty(work_root, work_error) &&
                    !work_error,
                "server work root is not empty before response publication");
    });

    activity.transition("publishing_response");
    publish_timing = timed_void([&] {
        publish_private_file(response_path, response_bytes);
        std::vector<std::uint8_t>().swap(response_bytes);
    });
    const std::int64_t response_published = unix_milliseconds();

    const Timing witness_packing_timing{
        replay_report.laned_witness_packing_wall_ms,
        replay_report.laned_witness_packing_cpu_ms};
    const Timing payload_evaluation_timing{
        std::max(0.0, evaluation_timing.wall_ms -
                          witness_packing_timing.wall_ms),
        std::max(0.0, evaluation_timing.cpu_ms -
                          witness_packing_timing.cpu_ms)};
    // The outer proof timer includes the tiny orchestration gaps around the
    // two measured suffixes. Attribute those gaps to GKR so the three public
    // proof phases reconcile exactly to the end-to-end server clock.
    gkr_timing.wall_ms += std::max(
        0.0, proof_timing.wall_ms - gkr_timing.wall_ms -
                 transcript_packing_timing.wall_ms);
    gkr_timing.cpu_ms += std::max(
        0.0, proof_timing.cpu_ms - gkr_timing.cpu_ms -
                 transcript_packing_timing.cpu_ms);
    const Timing proof_generation_timing = add_timings(
        {witness_packing_timing, gkr_timing,
         transcript_packing_timing});

    const Timing per_request = add_timings(
        {recurring_pre_request_timing, request_file.second,
         request_capacity_timing, decode_timing, evaluation_timing,
         proof_timing, proof_validation_timing, encode_timing,
         finalize_timing, publish_timing});
    const Timing process_timing = process_stopwatch.stop();
    const std::int64_t process_finished = unix_milliseconds();
    CompletedResultReport result(command.run_directory / "server" /
                                 "result.txt");
    const Record output(result.mirror());
    output.text("format", "laminate-packed-benchmark-server-v1");
    emit_identity(output, command, record);
    emit_geometry(output, record);
    emit_gate_mle_parameters(output, *workload.public_setup().outsourced_gate_mle);
    output.integer("timing.server.started_unix_ms", process_started);
    output.integer("timing.server.request_observed_unix_ms",
                   request_observed);
    output.integer("timing.server.response_published_unix_ms",
                   response_published);
    output.integer("timing.server.finished_unix_ms", process_finished);
    emit_exact_timing(output,
                      "timing.server.startup.load_preprocessing",
                      load_timing);
    emit_exact_timing(output,
                      "timing.server.startup.certify_replay_and_gkr_static",
                      static_planning_timing);
    emit_exact_timing(output,
                      "timing.server.startup.derive_persistent_reserve",
                      persistent_reserve_timing);
    emit_exact_timing(output,
                      "timing.server.recurring_pre_request.prepare_roots",
                      resource_roots_timing);
    emit_exact_timing(output,
                      "timing.server.recurring_pre_request.admit_transcript_packing",
                      admission_timing);
    emit_exact_timing(output,
                      "timing.server.recurring_pre_request.admit_checkpoint_and_host",
                      checkpoint_admission_timing);
    emit_exact_timing(output,
                      "timing.server.recurring_pre_request.total",
                      recurring_pre_request_timing);
    emit_exact_timing(output, "timing.server.startup.total",
                      startup_timing);
    output.text(
        "timing.server.startup.total.scope",
        "role-preprocessing-load-reusable-replay-gkr-static-certification-"
        "and-persistent-reserve-derivation;excludes-one-shot-request-"
        "resources-peer-idle-wait-and-per-request-work");
    output.text(
        "timing.server.recurring_pre_request.total.scope",
        "one-shot-work-root-creation-transcript-packing-admission-"
        "checkpoint-replay-scratch-and-host-capacity-admission;included-in-"
        "per-request-total-even-when-reserved-before-request-arrival");
    emit_exact_timing(output, "timing.server.wait_for_request",
                      wait_timing);
    emit_exact_timing(output, "timing.server.read_request_file",
                      request_file.second);
    emit_exact_timing(output,
                      "timing.server.validate_request_capacity",
                      request_capacity_timing);
    emit_exact_timing(output, "timing.server.decode_request",
                      decode_timing);
    emit_exact_timing(output, "timing.server.payload_evaluation",
                      payload_evaluation_timing);
    emit_exact_timing(output, "timing.server.prove.witness_packing",
                      witness_packing_timing);
    emit_exact_timing(output, "timing.server.prove.gkr", gkr_timing);
    emit_exact_timing(output,
                      "timing.server.prove.transcript_packing",
                      transcript_packing_timing);
    emit_exact_timing(output, "timing.server.prove",
                      proof_generation_timing);
    output.text(
        "timing.server.payload_evaluation.scope",
        "payload-FHE-only;excludes-Laned-witness-packing-even-when-"
        "packing-runs-at-each-completed-forward-layer-boundary");
    output.text(
        "timing.server.prove.scope",
        "logical-proof-generation-total;witness-packing-plus-encrypted-"
        "GKR-plus-transcript-packing");
    emit_exact_timing(output,
                      "timing.server.validate_proof_resource_reports",
                      proof_validation_timing);
    emit_exact_timing(output, "timing.server.encode_response",
                      encode_timing);
    emit_exact_timing(output,
                      "timing.server.finalize_and_retire_work",
                      finalize_timing);
    emit_exact_timing(output, "timing.server.publish_response",
                      publish_timing);
    emit_exact_timing(output, "timing.server.per_request_total",
                      per_request);
    emit_exact_timing(output, "timing.server.process_total",
                      process_timing);
    emit_seal_operation_counts(output, "server_payload_evaluation",
                               evaluation_counts);
    emit_seal_operation_counts(output, "server_proving",
                               proving_counts);
    output.text(
        "operations.server_payload_evaluation.scope",
        "chronological-forward-call;includes-layer-boundary-Laned-witness-"
        "packing;dedicated-witness-counters-follow");
    output.text(
        "operations.server_proving.scope",
        "online-GKR-and-transcript-packing-call;excludes-earlier-"
        "interleaved-Laned-witness-packing");
    output.integer("operations.server_witness_packing.source_values",
                   replay_report.laned_witness_source_values);
    output.integer(
        "operations.server_witness_packing.logical_values_packed",
        replay_report.laned_witness_logical_values_packed);
    output.integer(
        "operations.server_witness_packing.mask_preparations",
        replay_report.laned_witness_mask_preparations);
    output.integer(
        "operations.server_witness_packing.mask_cache_hits",
        replay_report.laned_witness_mask_cache_hits);
    output.integer(
        "memory.server_witness_packing.prepared_mask_ntt_bytes_created",
        replay_report.laned_witness_prepared_mask_ntt_bytes);
    output.integer(
        "memory.server_witness_packing.peak_mask_cache_ntt_bytes",
        replay_report.laned_witness_peak_mask_cache_ntt_bytes);
    output.integer("operations.server_witness_packing.modulus_switches",
                   replay_report.laned_witness_modulus_switches);
    output.integer(
        "operations.server_witness_packing.plain_multiplications",
        replay_report.laned_witness_plain_multiplications);
    output.integer("operations.server_witness_packing.additions",
                   replay_report.laned_witness_additions);
    output.integer("operations.server_witness_packing.rotations",
                   replay_report.laned_witness_rotations);
    output.integer("operations.server_witness_packing.packed_ciphertexts",
                   replay_report.laned_witness_packed_ciphertexts);
    output.text(
        "timing.server.per_request_total.scope",
        "recurring-one-shot-resource-admission-request-read-and-codec-"
        "payload-evaluation-checkpoint-replay-gkr-and-transcript-packing-"
        "proof-response-codec-and-publication;excludes-reusable-static-"
        "preprocessing-and-peer-idle-wait");
    output.integer("wire.request_bytes", request_bytes_count);
    output.integer("wire.response_bytes", response_bytes_count);
    if (folded_proof_size) {
        emit_packed_proof_sizes(output, response_bytes_count,
                                *folded_proof_size);
    } else {
        require(laned_proof_size.has_value(),
                "server omitted the proof-size breakdown");
        emit_packed_proof_sizes(output, response_bytes_count,
                                *laned_proof_size);
    }
    output.integer("storage.payload_replay_peak_live_physical_bytes",
                   replay_report.peak_live_physical_bytes);
    output.integer("storage.payload_replay_peak_live_scratch_bytes",
                   replay_report.peak_live_scratch_bytes);
    output.integer("storage.payload_replay_total_reclaimed_physical_bytes",
                   replay_report.total_reclaimed_physical_bytes);
    output.integer("storage.witness_packing_physical_bytes_written",
                   replay_report.laned_witness_physical_bytes_written);
    output.integer("storage.witness_packing_physical_bytes_retired",
                   replay_report.laned_witness_physical_bytes_retired);
    output.integer("storage.proof_ingress_ciphertexts",
                   replay_report.proof_ingress_ciphertexts);
    output.integer("storage.proof_ingress_modulus_switches",
                   replay_report.proof_ingress_modulus_switches);
    output.integer("work.payload_replay_units",
                   replay_report.replay_work_units);
    emit_replay_source_io(output, "forward", replay_report.forward);
    emit_replay_source_io(output, "reverse", replay_report.reverse_replay);
    emit_replay_source_io(output, "gkr_source",
                          replay_report.gkr_source_reads);
    output.integer("storage.gkr_peak_live_scratch_bytes",
                   gkr_peak_scratch);
    output.integer("work.gkr.multiplication_sort.artifacts",
                   gkr_sort.artifacts);
    output.integer("work.gkr.multiplication_sort.initial_runs",
                   gkr_sort.initial_runs);
    output.integer("work.gkr.multiplication_sort.runs_created",
                   gkr_sort.runs_created);
    output.integer("work.gkr.multiplication_sort.merge_passes",
                   gkr_sort.merge_passes);
    output.integer("work.gkr.multiplication_sort.maximum_open_runs",
                   gkr_sort.maximum_open_runs);
    output.integer("storage.gkr_multiplication_sort_temporary_bytes_written",
                   gkr_sort.temporary_bytes_written);
    output.integer(
        "memory.gkr_multiplication_sort_peak_buffered_payload_bytes",
        gkr_sort.peak_buffered_payload_bytes);
    output.integer("storage.gkr_multiplication_sort_retained_temporary_bytes",
                   gkr_sort.retained_temporary_bytes);
    emit_packing_storage(output, packing_report);
    output.integer("storage.server.admitted_peak_live_bytes",
                   final_storage_admission.max_local_disk_bytes);
    output.integer("memory.server.admitted_peak_resident_bytes",
                   final_storage_admission.max_resident_ram_bytes);
    output.integer(
        "memory.server.multiplication_sort_buffer_limit_bytes",
        process_multiplication_sort_buffer_bytes(record));
    output.integer("memory.client.admitted_peak_resident_bytes",
                   record.client_peak_resident_bytes);
    output.integer("memory.concurrent.admitted_peak_resident_bytes",
                   checked_add(
                       final_storage_admission.max_resident_ram_bytes,
                       record.client_peak_resident_bytes,
                       "reported concurrent resident peak"));
    output.integer("memory.server.peak_rss_bytes",
                   system_info().peak_rss_bytes);
    output.text("environment.command", exact_command(argc, argv));
    output.text("server.result", "PASS");
    progress.mark_complete(true);
    progress.emit(output);
    result.publish();
    activity.mark_complete();
    std::cout << "\nSERVER PASS\n";
    return 0;
}

struct LoadedProcessClient {
    ProcessSetupRecord record;
    AuthenticatedPackedClientOnlineState<SealBackend> client;
};

LoadedProcessClient load_process_client(
    const ProcessCommand &command, const PackedProcessProfile &profile) {
    ProcessSetupRecord record = load_setup_record(command, profile);
    require_client_host_ram(record);
    SealBackend::ClientContext client_context =
        SealBackend::deserialize_client_context_bundle(load_bundle(
            command.run_directory / "client" / "preprocessing" /
                "client-context.bin",
            record.client_bundle));
    SealBackend::PublicVerifierContext verifier_context =
        SealBackend::deserialize_public_verifier_context_bundle(
            load_bundle(command.run_directory / "client" /
                            "preprocessing" /
                            "public-verifier-context.bin",
                        record.verifier_bundle),
            record.fhe_context_storage_id,
            {
                .max_bundle_bytes = checked_size(
                    record.verifier_bundle.bytes, "verifier bundle"),
                .max_poly_modulus_degree = profile.slots,
                .max_rns_limbs =
                    profile.fresh_rns_limbs() + 1U,
            });
    auto client = open_authenticated_packed_client_online_state<
        SealBackend>(
        command.run_directory / "shared" / "preprocessing" /
            "packed-shared",
        command.run_directory / "client" / "preprocessing" /
            "packed-client",
        record.root_storage_identity, std::move(client_context),
        std::move(verifier_context),
        role_open_limits(record, profile));
    require(client.workload().semantic_identity() ==
                    record.workload_semantic_identity &&
                client.workload().setup_digest() ==
                    record.public_setup_digest &&
                client.workload().circuit_digest() == record.circuit_digest &&
                packed_workload_static_decode_requirements(
                    client.workload(),
                    checked_size(record.workload_max_bytes,
                                 "workload bytes")) ==
                    record.workload_decode,
            "client preprocessing identity mismatch");
    return LoadedProcessClient{std::move(record), std::move(client)};
}

int run_client(const ProcessCommand &command, int argc, char **argv) {
    Stopwatch process_stopwatch;
    const std::int64_t process_started = unix_milliseconds();
    const PackedProcessProfile profile =
        packed_process_profile(command.variant, command.tier,
                               command.lanes);
    require_profile_execution_policy_before_artifacts(profile);
    require_completed_setup(command);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "client" /
                              "activity.jsonl",
                          "client");
    ProtocolProgressJournal progress(command.run_directory / "client" /
                                     "progress.jsonl");

    activity.transition("loading_preprocessing");
    progress.phase("client.loading_preprocessing");
    auto loaded = timed([&] { return load_process_client(command, profile); });
    auto [record, client] = std::move(loaded.first);
    const Timing load_timing = loaded.second;

    activity.transition("constructing_deterministic_inputs");
    progress.phase("client.constructing_deterministic_inputs");
    auto inputs = timed([&] {
        return make_workload_inputs(workload_spec(profile));
    });

    const std::filesystem::path request_path =
        command.run_directory / "shared" / "transcript" /
        "cli-to-srv-request.bin";
    const std::filesystem::path response_path =
        command.run_directory / "shared" / "transcript" /
        "srv-to-cli-response.bin";
    std::size_t request_bytes_count = 0;
    std::size_t response_bytes_count = 0;
    Timing encryption_timing;
    Timing binding_timing;
    Timing nonce_timing;
    Timing encode_timing;
    Timing publish_timing;
    Timing wait_timing;
    Timing read_timing;
    Timing decode_timing;
    Timing open_timing;
    Timing verify_timing;
    Timing output_noise_audit_timing;
    std::optional<PackedOutputNoiseAudit> output_noise_audit;
    protocol::BaseVerifierTimings verifier_timings;
    verification_profile::VerificationBreakdown verification_components;
    std::int64_t request_published = 0;
    std::int64_t response_observed = 0;
    std::int64_t verification_finished = 0;

    if (command.variant == PackedProcessVariant::Folded) {
        activity.transition("encrypting_and_binding_request");
        progress.phase("client.encrypting_and_binding_request");
        auto encrypted = timed([&] {
            return encrypt_folded_request_inputs<SealBackend>(
                client, inputs.first);
        });
        encryption_timing = encrypted.second;
        auto entropy = timed([&] { return fresh_nonce_entropy(); });
        nonce_timing = entropy.second;
        auto begun = timed([&] {
            return bind_folded_request_session<SealBackend>(
                client, inputs.first, std::move(encrypted.first),
                make_folded_client_nonce(entropy.first));
        });
        auto started = std::move(begun.first);
        binding_timing = begun.second;

        activity.transition("encoding_request");
        auto encoded = timed([&] {
            return encode_folded_evaluation_request<SealBackend>(
                client.client_context(), started.request,
                record.request_wire_bytes);
        });
        encode_timing = encoded.second;
        request_bytes_count = encoded.first.size();
        activity.transition("publishing_request");
        require_free_disk(command.run_directory, record.request_wire_bytes,
                          record.capacity.min_free_disk_bytes);
        publish_timing = timed_void([&] {
            require(encoded.first.size() <= record.request_wire_bytes,
                    "encoded request exceeds setup-derived wire cap");
            publish_private_file(request_path, encoded.first);
        });
        request_published = unix_milliseconds();
        started.request.encrypted_inputs.clear();
        std::vector<std::uint8_t>().swap(encoded.first);

        std::cout << "CLIENT REQUEST PUBLISHED\n";
        wait_timing = wait_for_artifact(
            response_path, "client", "server response", activity,
            "waiting_for_server_response",
            command.run_directory / "server" / "failure.txt",
            command.run_directory / "server" / "activity.jsonl");
        response_observed = unix_milliseconds();
        activity.transition("reading_response_file");
        auto response_file = timed([&] {
            return read_bounded_file(response_path,
                                     record.response_wire_bytes);
        });
        read_timing = response_file.second;
        response_bytes_count = response_file.first.size();

        activity.transition("decoding_response");
        auto decoded = timed([&] {
            auto response = decode_folded_response<SealBackend>(
                client, response_file.first,
                folded_wire_limits(record, true),
                packed_proof_limits(record),
                TraceProvenance::FheEvaluated);
            std::vector<std::uint8_t>().swap(response_file.first);
            return response;
        });
        decode_timing = decoded.second;
        auto response = std::move(decoded.first);

        auto transcript = [&] {
            verification_profile::ScopedVerificationSession session(verification_components);
            verification_profile::ScopedVerificationPhase recovery(
                verification_profile::Category::Recovery);
            return Transcript(kProcessTranscriptDomain);
        }();
        activity.transition("opening_response");
        auto opened = timed([&] {
            verification_profile::ScopedVerificationSession session(verification_components);
            return open_folded_response<SealBackend>(
                client, std::move(started.state), response, transcript);
        });
        open_timing = opened.second;
        if (!opened.first) {
            throw std::runtime_error("client rejected folded response");
        }
        activity.transition("verifying_proof");
        progress.phase("client.verifying_proof");
        protocol::FoldedVerifierTimings detailed;
        PackedClientVerificationProgress verification_progress_state;
        RuntimeProgressCallback verification_progress =
            tracked_client_verification_progress(
                progress, verification_progress_state);
        auto verified = timed([&] {
            verification_profile::ScopedVerificationSession session(verification_components);
            auto result =
                verify_opened_folded_response_profiled<SealBackend>(
                client, std::move(*opened.first), response, transcript,
                detailed,
                verification_progress);
            return result;
        });
        verify_timing = verified.second;
        verifier_timings = detailed;
        if (!verified.first ||
            verified.first->size() != record.output_ciphertexts) {
            throw std::runtime_error(packed_client_verification_rejection(
                "LaminateFolded",
                verified.first
                    ? std::optional<std::size_t>(verified.first->size())
                    : std::nullopt,
                checked_size(record.output_ciphertexts,
                             "expected output ciphertext count"),
                detailed.transcript_packing_threshold,
                verification_progress_state));
        }
        verification_finished = unix_milliseconds();
        publish_client_proof_verification_checkpoint(
            command, verification_finished);
        activity.transition("auditing_honest_output_noise");
        progress.phase("client.auditing_honest_output_noise");
        auto audited = timed([&] {
            return audit_packed_output_noise(
                client.client_context(), client.verifier_context(),
                response.output.values,
                checked_size(record.output_ciphertexts,
                             "expected output ciphertext count"));
        });
        output_noise_audit = audited.first;
        output_noise_audit_timing = audited.second;
        publish_client_output_noise_checkpoint(
            command, *output_noise_audit,
            profile.evidence == PackedProcessEvidence::Evaluation);
        if (profile.evidence == PackedProcessEvidence::Evaluation) {
            require_packed_output_noise_target(*output_noise_audit);
        }
        response = FoldedResponse<SealBackend>{};
    } else {
        activity.transition("encrypting_and_binding_request");
        progress.phase("client.encrypting_and_binding_request");
        auto encrypted = timed([&] {
            return encrypt_laned_request_inputs<SealBackend>(
                client, inputs.first);
        });
        encryption_timing = encrypted.second;
        auto entropy = timed([&] { return fresh_nonce_entropy(); });
        nonce_timing = entropy.second;
        auto begun = timed([&] {
            return bind_laned_request_session<SealBackend>(
                client, inputs.first, std::move(encrypted.first),
                make_laned_client_nonce(entropy.first));
        });
        auto started = std::move(begun.first);
        binding_timing = begun.second;

        activity.transition("encoding_request");
        auto encoded = timed([&] {
            return encode_laned_evaluation_request<SealBackend>(
                client.client_context(), started.request,
                record.request_wire_bytes);
        });
        encode_timing = encoded.second;
        request_bytes_count = encoded.first.size();
        activity.transition("publishing_request");
        require_free_disk(command.run_directory, record.request_wire_bytes,
                          record.capacity.min_free_disk_bytes);
        publish_timing = timed_void([&] {
            require(encoded.first.size() <= record.request_wire_bytes,
                    "encoded request exceeds setup-derived wire cap");
            publish_private_file(request_path, encoded.first);
        });
        request_published = unix_milliseconds();
        started.request.encrypted_inputs.clear();
        std::vector<std::uint8_t>().swap(encoded.first);

        std::cout << "CLIENT REQUEST PUBLISHED\n";
        wait_timing = wait_for_artifact(
            response_path, "client", "server response", activity,
            "waiting_for_server_response",
            command.run_directory / "server" / "failure.txt",
            command.run_directory / "server" / "activity.jsonl");
        response_observed = unix_milliseconds();
        activity.transition("reading_response_file");
        auto response_file = timed([&] {
            return read_bounded_file(response_path,
                                     record.response_wire_bytes);
        });
        read_timing = response_file.second;
        response_bytes_count = response_file.first.size();

        activity.transition("decoding_response");
        auto decoded = timed([&] {
            auto response = decode_laned_response<SealBackend>(
                client, response_file.first,
                laned_wire_limits(record, true),
                packed_proof_limits(record),
                TraceProvenance::FheEvaluated);
            std::vector<std::uint8_t>().swap(response_file.first);
            return response;
        });
        decode_timing = decoded.second;
        auto response = std::move(decoded.first);

        auto transcript = [&] {
            verification_profile::ScopedVerificationSession session(verification_components);
            verification_profile::ScopedVerificationPhase recovery(
                verification_profile::Category::Recovery);
            return Transcript(kProcessTranscriptDomain);
        }();
        activity.transition("opening_response");
        auto opened = timed([&] {
            verification_profile::ScopedVerificationSession session(verification_components);
            return open_laned_response<SealBackend>(
                client, std::move(started.state), response, transcript);
        });
        open_timing = opened.second;
        if (!opened.first) {
            throw std::runtime_error("client rejected laned response");
        }
        activity.transition("verifying_proof");
        progress.phase("client.verifying_proof");
        protocol::LanedVerifierTimings detailed;
        PackedClientVerificationProgress verification_progress_state;
        RuntimeProgressCallback verification_progress =
            tracked_client_verification_progress(
                progress, verification_progress_state);
        auto verified = timed([&] {
            verification_profile::ScopedVerificationSession session(verification_components);
            auto result =
                verify_opened_laned_response_profiled<SealBackend>(
                client, std::move(*opened.first), response, transcript,
                detailed,
                verification_progress);
            return result;
        });
        verify_timing = verified.second;
        verifier_timings = detailed;
        if (!verified.first ||
            verified.first->size() != record.output_ciphertexts) {
            throw std::runtime_error(packed_client_verification_rejection(
                "LaminateLaned",
                verified.first
                    ? std::optional<std::size_t>(verified.first->size())
                    : std::nullopt,
                checked_size(record.output_ciphertexts,
                             "expected output ciphertext count"),
                detailed.transcript_packing_threshold,
                verification_progress_state));
        }
        verification_finished = unix_milliseconds();
        publish_client_proof_verification_checkpoint(
            command, verification_finished);
        activity.transition("auditing_honest_output_noise");
        progress.phase("client.auditing_honest_output_noise");
        auto audited = timed([&] {
            return audit_packed_output_noise(
                client.client_context(), client.verifier_context(),
                response.output.values,
                checked_size(record.output_ciphertexts,
                             "expected output ciphertext count"));
        });
        output_noise_audit = audited.first;
        output_noise_audit_timing = audited.second;
        publish_client_output_noise_checkpoint(
            command, *output_noise_audit,
            profile.evidence == PackedProcessEvidence::Evaluation);
        if (profile.evidence == PackedProcessEvidence::Evaluation) {
            require_packed_output_noise_target(*output_noise_audit);
        }
        response = LanedResponse<SealBackend>{};
    }

    require(output_noise_audit.has_value() && verification_finished != 0,
            "packed client omitted the post-verification output-noise audit");

    const Timing process_timing = process_stopwatch.stop();
    const std::int64_t process_finished = unix_milliseconds();
    CompletedResultReport result(command.run_directory / "client" /
                                 "result.txt");
    const Record output(result.mirror());
    output.text("format", "laminate-packed-benchmark-client-v3");
    emit_identity(output, command, record);
    emit_geometry(output, record);
    emit_gate_mle_parameters(output, *client.workload().public_setup().outsourced_gate_mle);
    emit_exact_timing(output, "timing.client.load_preprocessing",
                      load_timing);
    emit_exact_timing(output, "timing.client.construct_inputs",
                      inputs.second);
    emit_exact_timing(output, "timing.client.encrypt_inputs",
                      encryption_timing);
    emit_exact_timing(output, "timing.client.generate_nonce", nonce_timing);
    emit_exact_timing(output, "timing.client.bind_request_session",
                      binding_timing);
    emit_exact_timing(output, "timing.client.encode_request",
                      encode_timing);
    emit_exact_timing(output, "timing.client.publish_request",
                      publish_timing);
    emit_exact_timing(output, "timing.client.wait_for_response",
                      wait_timing);
    emit_exact_timing(output, "timing.client.read_response_file",
                      read_timing);
    emit_exact_timing(output, "timing.client.decode_response",
                      decode_timing);
    emit_exact_timing(output, "timing.client.open_response", open_timing);
    emit_exact_timing(output, "timing.client.verify", verify_timing);
    emit_exact_timing(output, "timing.client.honest_output_noise_audit",
                      output_noise_audit_timing);
    emit_verifier_timings(output, verifier_timings);
    const Timing per_request = emit_client_computation(
        output, encryption_timing, verification_components);
    emit_exact_timing(output, "timing.client.per_request_total",
                      per_request);
    emit_exact_timing(output, "timing.client.process_total",
                      process_timing);
    output.integer("timing.client.process_started_unix_ms",
                   process_started);
    output.integer("timing.client.started_unix_ms", process_started);
    output.integer("timing.client.request_published_unix_ms",
                   request_published);
    output.integer("timing.client.response_observed_unix_ms",
                   response_observed);
    output.integer("timing.client.verification_finished_unix_ms",
                   verification_finished);
    output.integer("timing.client.process_finished_unix_ms",
                   process_finished);
    output.integer("timing.client.finished_unix_ms", process_finished);
    output.text("timing.client.per_request_total.scope",
                std::string(kClientComputationScope));
    emit_packed_output_noise_audit(
        output, *output_noise_audit,
        profile.evidence == PackedProcessEvidence::Evaluation);
    output.integer("wire.request_bytes", request_bytes_count);
    output.integer("wire.response_bytes", response_bytes_count);
    output.integer("memory.client.peak_rss_bytes",
                   system_info().peak_rss_bytes);
    output.integer("memory.client.admitted_peak_resident_bytes",
                   record.client_peak_resident_bytes);
    output.text("environment.command", exact_command(argc, argv));
    output.text("verification.result", "PASS");
    progress.mark_complete(true);
    progress.emit(output);
    result.publish();
    activity.mark_complete();
    std::cout << "\nCLIENT VERIFICATION PASS\n";
    return 0;
}

int audit_existing_output(const ProcessCommand &command, int argc,
                          char **argv) {
    const PackedProcessProfile profile = packed_process_profile(
        command.variant, command.tier, command.lanes);
    require_profile_execution_policy_before_artifacts(profile);
    require_completed_setup(command);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    auto [record, client] = load_process_client(command, profile);

    const std::filesystem::path response_path =
        command.run_directory / "shared" / "transcript" /
        "srv-to-cli-response.bin";
    const std::vector<std::uint8_t> response_bytes = read_bounded_file(
        response_path, record.response_wire_bytes);

    PackedOutputNoiseAudit audit;
    if (command.variant == PackedProcessVariant::Folded) {
        const FoldedResponse<SealBackend> response =
            decode_folded_response<SealBackend>(
                client, response_bytes, folded_wire_limits(record, true),
                packed_proof_limits(record),
                TraceProvenance::FheEvaluated);
        audit = audit_packed_output_noise(
            client.client_context(), client.verifier_context(),
            response.output.values,
            checked_size(record.output_ciphertexts,
                         "expected output ciphertext count"));
    } else {
        const LanedResponse<SealBackend> response =
            decode_laned_response<SealBackend>(
                client, response_bytes, laned_wire_limits(record, true),
                packed_proof_limits(record),
                TraceProvenance::FheEvaluated);
        audit = audit_packed_output_noise(
            client.client_context(), client.verifier_context(),
            response.output.values,
            checked_size(record.output_ciphertexts,
                         "expected output ciphertext count"));
    }

    const bool target_pass = packed_output_noise_target_passes(audit);
    const Record output;
    output.text("format", "laminate-packed-output-noise-audit-v1");
    output.text("classification.execution", "single-thread");
    output.text("classification.scope",
                "read-only-existing-response;proof-verification-not-repeated");
    emit_identity(output, command, record);
    emit_gate_mle_parameters(output, *client.workload().public_setup().outsourced_gate_mle);
    output.integer("wire.response_bytes", response_bytes.size());
    emit_packed_output_noise_audit(output, audit, true);
    output.text("noise.final_output.scope",
                "read-only-existing-response;proof-verification-not-"
                "repeated");
    output.text("environment.command", exact_command(argc, argv));
    return target_pass ? 0 : 1;
}

std::optional<std::string_view> activity_json_value(
    std::string_view line, std::string_view key) {
    const std::string marker = "\"" + std::string(key) + "\":";
    const std::size_t position = line.find(marker);
    if (position == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t begin = position + marker.size();
    if (begin >= line.size()) {
        return std::nullopt;
    }
    if (line[begin] == '"') {
        ++begin;
        const std::size_t end = line.find('"', begin);
        return end == std::string_view::npos
                   ? std::nullopt
                   : std::optional<std::string_view>(
                         line.substr(begin, end - begin));
    }
    const std::size_t end = line.find_first_of(",}", begin);
    return line.substr(begin, end == std::string_view::npos
                                  ? line.size() - begin
                                  : end - begin);
}

std::string progress_elapsed(std::string_view milliseconds);

std::optional<std::string> last_progress_phase_line(
    const std::filesystem::path &path) {
    std::ifstream input(path);
    if (!input) {
        return std::nullopt;
    }
    std::optional<std::string> result;
    for (std::string line; std::getline(input, line);) {
        if (input.eof()) {
            break;
        }
        if (!line.empty() && activity_json_value(line, "stage")) {
            result = std::move(line);
        }
    }
    return result;
}

bool progress_reached_stage(const std::filesystem::path &path,
                            std::string_view expected_stage) {
    std::ifstream input(path);
    for (std::string line; std::getline(input, line);) {
        if (activity_json_value(line, "stage") == expected_stage) {
            return true;
        }
    }
    return false;
}

void print_client_progress(const std::filesystem::path &path) {
    const std::optional<std::string> line =
        last_progress_phase_line(path);
    if (!line) {
        return;
    }
    const auto event = activity_json_value(*line, "event");
    const auto stage = activity_json_value(*line, "stage");
    if (!stage) {
        return;
    }
    const ProtocolProgressDescriptionView description{
        .stage = *stage,
        .layer_kind = activity_json_value(*line, "layer_kind")
                          .value_or("unspecified"),
        .side = activity_json_value(*line, "side")
                    .value_or("unspecified"),
        .coordinate_domain =
            activity_json_value(*line, "coordinate_domain")
                .value_or("unspecified"),
        .reduction_layer = protocol_progress_parse_index(
            activity_json_value(*line, "reduction_layer")),
        .source_layer = protocol_progress_parse_index(
            activity_json_value(*line, "source_layer")),
        .output_layer = protocol_progress_parse_index(
            activity_json_value(*line, "output_layer")),
        .checkpoint_layer = protocol_progress_parse_index(
            activity_json_value(*line, "checkpoint_layer")),
        .round = protocol_progress_parse_index(
            activity_json_value(*line, "round")),
        .round_count = protocol_progress_parse_index(
            activity_json_value(*line, "rounds"), 0),
    };
    std::cout << "  client telemetry: ";
    if (event && *event == "end") {
        std::cout << "last completed ";
    } else if (event && *event == "phase") {
        std::cout << "last phase ";
    } else {
        std::cout << "last active ";
    }
    std::cout << protocol_progress_human_description(description);
    if (const auto elapsed =
            activity_json_value(*line, "run_elapsed_ms")) {
        std::cout << " (event recorded at client elapsed "
                  << progress_elapsed(*elapsed) << ')';
    }
    std::cout << '\n';
}

void print_client_failure(const std::filesystem::path &path) {
    const std::optional<std::string> published = published_failure(path);
    if (!published) {
        return;
    }
    std::string message = *published;
    while (!message.empty() &&
           (message.back() == '\n' || message.back() == '\r')) {
        message.pop_back();
    }
    std::cout << "  client failure: " << clean(std::move(message)) << '\n';
}

void print_role_status(std::string_view role,
                       const RoleProcessSnapshot &process,
                       bool terminal) {
    std::cout << "  " << role << " process: ";
    switch (process.state) {
    case RoleProcessState::Missing:
        std::cout << (terminal ? "finished" : "not started");
        break;
    case RoleProcessState::Active:
        std::cout << "ACTIVE";
        break;
    case RoleProcessState::Inactive:
        std::cout << (terminal ? "finished" : "NOT RUNNING (incomplete)");
        break;
    case RoleProcessState::Invalid:
        std::cout << "unknown (" << process.diagnostic << ')';
        break;
    }
    if (process.last_line) {
        if (const auto stage =
                activity_json_value(*process.last_line, "stage")) {
            std::string readable(*stage);
            std::replace(readable.begin(), readable.end(), '_', ' ');
            std::cout << "; last stage: " << readable;
        }
    }
    std::cout << '\n';
}

std::string progress_elapsed(std::string_view milliseconds) {
    std::istringstream input{std::string(milliseconds)};
    double value = 0;
    input >> value;
    if (!input || value < 0) {
        return "unknown elapsed time";
    }
    const auto total_seconds =
        static_cast<std::uint64_t>(value / 1000.0);
    std::ostringstream output;
    output << std::setfill('0') << std::setw(2) << total_seconds / 3600U
           << ':' << std::setw(2) << (total_seconds / 60U) % 60U << ':'
           << std::setw(2) << total_seconds % 60U;
    return output.str();
}

void print_server_progress(const std::filesystem::path &path,
                           const RoleProcessSnapshot &server_process) {
    const std::optional<std::string> line = last_complete_line(path);
    bool payload_active = false;
    if (server_process.state == RoleProcessState::Active &&
        server_process.last_line) {
        if (const auto role_stage =
                activity_json_value(*server_process.last_line, "stage")) {
            payload_active = *role_stage == "payload_evaluation";
        }
    }
    if (!line) {
        if (payload_active) {
            std::cout << "  server proof phase: payload evaluation; GKR "
                         "sumcheck has not started\n";
        }
        return;
    }

    const auto event = activity_json_value(*line, "event");
    const auto stage = activity_json_value(*line, "stage");
    const auto status = activity_json_value(*line, "status");
    const auto elapsed = activity_json_value(*line, "run_elapsed_ms");
    const auto layer_kind = activity_json_value(*line, "layer_kind");
    const auto coordinate_domain =
        activity_json_value(*line, "coordinate_domain");
    const auto subpass = activity_json_value(*line, "subpass");
    const auto reduction = activity_json_value(*line, "reduction_layer");
    const auto source = activity_json_value(*line, "source_layer");
    const auto output_layer = activity_json_value(*line, "output_layer");
    const auto checkpoint = activity_json_value(*line, "checkpoint_layer");
    const auto side = activity_json_value(*line, "side");
    const auto round = activity_json_value(*line, "round");
    const auto rounds = activity_json_value(*line, "rounds");
    const ProtocolProgressDescriptionView description{
        .stage = stage.value_or("unspecified"),
        .layer_kind = layer_kind.value_or("unspecified"),
        .side = side.value_or("unspecified"),
        .coordinate_domain = coordinate_domain.value_or("unspecified"),
        .subpass = subpass.value_or("unspecified"),
        .reduction_layer = protocol_progress_parse_index(reduction),
        .source_layer = protocol_progress_parse_index(source),
        .output_layer = protocol_progress_parse_index(output_layer),
        .checkpoint_layer = protocol_progress_parse_index(checkpoint),
        .round = protocol_progress_parse_index(round),
        .round_count = protocol_progress_parse_index(rounds, 0),
    };
    std::cout << "  server telemetry: ";
    if (status) {
        std::cout << *status;
    } else if (event && stage) {
        if (*event == "begin") {
            std::cout << "current ";
        } else if (*event == "progress") {
            std::cout << "current ";
        } else if (*event == "end") {
            std::cout << "last completed ";
        } else if (*event == "phase") {
            std::cout << "current ";
        } else {
            std::cout << "last " << *event << " for ";
        }
        std::cout << protocol_progress_human_description(description);
    } else {
        std::cout << "present; last line could not be summarized";
    }
    if (elapsed) {
        std::cout << " (event recorded at server elapsed "
                  << progress_elapsed(*elapsed) << ')';
    }
    std::cout << '\n';

    const auto work_units = activity_json_value(*line, "work_units");
    const auto completed_steps =
        activity_json_value(*line, "completed_steps");
    const auto total_steps = activity_json_value(*line, "total_steps");
    const auto completed_work_units =
        activity_json_value(*line, "completed_work_units");
    const auto total_work_units =
        activity_json_value(*line, "total_work_units");
    const auto progress_work_unit =
        activity_json_value(*line, "progress_work_unit");
    const auto phase_completed_steps =
        activity_json_value(*line, "phase_completed_steps");
    const auto phase_total_steps =
        activity_json_value(*line, "phase_total_steps");
    const auto completed_read_bytes =
        activity_json_value(*line, "completed_read_bytes");
    const auto total_read_bytes =
        activity_json_value(*line, "total_read_bytes");
    const auto completed_write_bytes =
        activity_json_value(*line, "completed_write_bytes");
    const auto total_write_bytes =
        activity_json_value(*line, "total_write_bytes");
    const auto phase_completed_read_bytes =
        activity_json_value(*line, "phase_completed_read_bytes");
    const auto phase_total_read_bytes =
        activity_json_value(*line, "phase_total_read_bytes");
    const auto phase_completed_write_bytes =
        activity_json_value(*line, "phase_completed_write_bytes");
    const auto phase_total_write_bytes =
        activity_json_value(*line, "phase_total_write_bytes");
    const auto completed_butterflies =
        activity_json_value(*line, "completed_butterflies");
    const auto total_butterflies =
        activity_json_value(*line, "total_butterflies");
    const auto phase_completed_butterflies =
        activity_json_value(*line, "phase_completed_butterflies");
    const auto phase_total_butterflies =
        activity_json_value(*line, "phase_total_butterflies");
    const auto radix_elements =
        activity_json_value(*line, "radix_elements");
    const auto row_count = activity_json_value(*line, "row_count");
    const auto row_size = activity_json_value(*line, "row_size");
    const auto recent_throughput =
        activity_json_value(*line, "recent_work_units_per_second");
    const auto estimated_remaining =
        activity_json_value(*line, "estimated_remaining_ms");
    const auto column_index =
        activity_json_value(*line, "column_index");
    const auto column_count =
        activity_json_value(*line, "column_count");
    const bool witness_commitment_progress =
        stage && stage->starts_with(
                     "transcript_packing.spartan.witness_commitment.");
    if (work_units || total_steps || total_work_units || column_count ||
        phase_total_steps || total_read_bytes || total_write_bytes ||
        phase_total_butterflies || radix_elements || row_count || row_size ||
        recent_throughput) {
        std::cout << "    detail:";
        bool first_detail = true;
        const auto separate_detail = [&] {
            std::cout << (first_detail ? " " : ", ");
            first_detail = false;
        };
        if (work_units) {
            separate_detail();
            std::cout << "work units " << *work_units;
        }
        if (column_index && column_count) {
            std::istringstream input{std::string(*column_index)};
            std::uint64_t zero_based = 0;
            if (input >> zero_based) {
                separate_detail();
                std::cout << "column " << zero_based + 1U
                          << " of " << *column_count;
            }
        }
        if (completed_steps && total_steps) {
            separate_detail();
            if (witness_commitment_progress) {
                std::cout << "commitment artifact passes "
                          << *completed_steps << " of " << *total_steps;
            } else if (stage &&
                       (stage->starts_with("payload.forward_relation") ||
                        stage->starts_with("payload.replay_relation"))) {
                std::cout << "output records " << *completed_steps << " of "
                          << *total_steps;
            } else if (stage &&
                       stage->starts_with("laned.witness_packing")) {
                std::cout << "source values " << *completed_steps << " of "
                          << *total_steps;
            } else {
                std::cout << "completed steps " << *completed_steps << " of "
                          << *total_steps;
            }
        }
        if (phase_completed_steps && phase_total_steps) {
            separate_detail();
            std::cout << "active-phase passes " << *phase_completed_steps
                      << " of " << *phase_total_steps;
        }
        if (completed_work_units && total_work_units) {
            separate_detail();
            std::cout << "current-pass "
                      << *completed_work_units << " of "
                      << *total_work_units;
            if (progress_work_unit) {
                std::cout << ' ' << *progress_work_unit;
            }
        }
        if (radix_elements) {
            separate_detail();
            std::cout << "radix " << *radix_elements;
        }
        if (row_count && row_size) {
            separate_detail();
            std::cout << *row_count << " rows x " << *row_size
                      << " elements";
        }
        if (completed_read_bytes && total_read_bytes) {
            separate_detail();
            std::cout << "current-pass read bytes "
                      << *completed_read_bytes << " of "
                      << *total_read_bytes;
        }
        if (completed_write_bytes && total_write_bytes) {
            separate_detail();
            std::cout << "current-pass written bytes "
                      << *completed_write_bytes << " of "
                      << *total_write_bytes;
        }
        if (phase_completed_read_bytes && phase_total_read_bytes) {
            separate_detail();
            std::cout << "active-phase read bytes "
                      << *phase_completed_read_bytes << " of "
                      << *phase_total_read_bytes;
        }
        if (phase_completed_write_bytes && phase_total_write_bytes) {
            separate_detail();
            std::cout << "active-phase written bytes "
                      << *phase_completed_write_bytes << " of "
                      << *phase_total_write_bytes;
        }
        if (completed_butterflies && total_butterflies) {
            separate_detail();
            std::cout << "current-pass butterflies "
                      << *completed_butterflies << " of "
                      << *total_butterflies;
        }
        if (phase_completed_butterflies && phase_total_butterflies) {
            separate_detail();
            std::cout << "active-phase butterflies "
                      << *phase_completed_butterflies << " of "
                      << *phase_total_butterflies;
        }
        if (recent_throughput) {
            separate_detail();
            std::cout << "recent " << *recent_throughput;
            if (progress_work_unit) {
                std::cout << ' ' << *progress_work_unit;
            }
            std::cout << "/s";
            if (estimated_remaining) {
                std::cout << ", current-pass ETA "
                          << progress_elapsed(*estimated_remaining);
            }
        }
        std::cout << '\n';
    }

    print_payload_relation_snapshot(std::cout, *line,
                                    activity_json_value);

    if (!stage) {
        return;
    }
    if (stage->starts_with("payload.forward_relation")) {
        std::cout << "  server proof phase: payload evaluation; GKR "
                     "sumcheck has not started\n";
    } else if (stage->starts_with("laned.witness_packing")) {
        std::cout << "  server proof phase: witness packing (phase 1 of 3), "
                     "after the completed payload layer\n";
    } else if (stage->starts_with("payload.replay_segment") ||
               stage->starts_with("payload.replay_relation") ||
               stage->starts_with("payload.proof_ingress")) {
        std::cout << "  server proof phase: encrypted GKR checkpoint replay "
                     "and source preparation\n";
    } else if (stage->starts_with("folded.") ||
               stage->starts_with("laned.")) {
        std::cout << "  server proof phase: encrypted GKR reduction and "
                     "sumcheck\n";
    } else if (stage->starts_with("transcript_packing.spartan")) {
        std::cout << "  server proof phase: external Spartan transcript-"
                     "packing proof ("
                  << *stage << ")\n";
    } else if (stage->starts_with("transcript_packing.")) {
        std::cout << "  server proof phase: transcript-packing proof ("
                  << *stage << ")\n";
    } else if (*stage == "server.payload_evaluation") {
        std::cout << "  server proof phase: payload evaluation; GKR "
                     "sumcheck has not started\n";
    } else if (*stage == "server.proving") {
        std::cout << "  server proof phase: GKR/transcript-packing proof "
                     "orchestration\n";
    }
}

int run_status(const ProcessCommand &command) {
    std::error_code error;
    require(std::filesystem::is_directory(command.run_directory, error) &&
                !error,
            "status requires an existing setup-created run directory");
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    const auto path = [&](std::string_view relative) {
        return command.run_directory / relative;
    };
    bool diagnostic_ciphertext_hash = command.tier == PackedProcessTier::Quick;
    bool has_setup = false;
    if (regular_file_exists(path("shared/setup.bin"))) {
        // Status binds the recorded identity without executing a proof.
        // Execution additionally checks the complete setup policy.
        const ProcessSetupRecord recorded = decode_setup(read_bounded_file(
            path("shared/setup.bin"), kMaximumSetupRecordBytes));
        require(recorded.variant == command.variant_name &&
                    recorded.profile == command.profile_name &&
                    recorded.slots == kDefaultPolyModulusDegree &&
                    recorded.lanes == command.lanes,
                "status selector does not match setup record identity");
        require_run_binding(command, recorded);
        has_setup = true;
        diagnostic_ciphertext_hash =
            gkr::CiphertextCommitmentPolicy::from_wire_code(
                recorded.ciphertext_commitment_policy_code).is_diagnostic_only();
    }

    const ProcessCompletion setup = inspect_process_completion(
        regular_file_exists(path("shared/setup.bin")) &&
            result_contains(path("shared/setup-result.txt"),
                            "setup.result=PASS"),
        path("shared/setup-result.txt"),
        path("shared/setup-process-exit.txt"),
        path("shared/setup-failure.txt"));
    const ProcessCompletion server = inspect_process_completion(
        result_contains(path("server/result.txt"), "server.result=PASS"),
        path("server/result.txt"), path("server/process-exit.txt"),
        path("server/failure.txt"));
    const ProcessCompletion client = inspect_process_completion(
        result_contains(path("client/result.txt"),
                        "verification.result=PASS"),
        path("client/result.txt"), path("client/process-exit.txt"),
        path("client/failure.txt"));
    const bool proof_verification_pass =
        result_contains(path("client/result.txt"),
                        "verification.result=PASS") ||
        result_contains(path("client/proof-verification-result.txt"),
                        "verification.result=PASS") ||
        progress_reached_stage(
            path("client/progress.jsonl"),
            "client.auditing_honest_output_noise");
    const bool output_noise_pass =
        result_contains(path("client/result.txt"),
                        "noise.final_output.target_result=PASS") ||
        result_contains(path("client/output-noise-result.txt"),
                        "noise.final_output.target_result=PASS");
    const bool output_noise_failed =
        result_contains(path("client/output-noise-result.txt"),
                        "noise.final_output.target_result=FAIL");
    const bool output_noise_diagnostic =
        result_contains(
            path("client/result.txt"),
            "noise.final_output.target_result=NOT-ENFORCED-DIAGNOSTIC") ||
        result_contains(
            path("client/output-noise-result.txt"),
            "noise.final_output.target_result=NOT-ENFORCED-DIAGNOSTIC");
    const bool output_noise_started = progress_reached_stage(
        path("client/progress.jsonl"),
        "client.auditing_honest_output_noise");
    const RoleProcessSnapshot setup_process =
        inspect_role_process(path("shared/setup-activity.jsonl"));
    const RoleProcessSnapshot server_process =
        inspect_role_process(path("server/activity.jsonl"));
    const RoleProcessSnapshot client_process =
        inspect_role_process(path("client/activity.jsonl"));
    const bool invalid =
        setup_process.state == RoleProcessState::Invalid ||
        server_process.state == RoleProcessState::Invalid ||
        client_process.state == RoleProcessState::Invalid;
    const bool active = setup_process.state == RoleProcessState::Active ||
                        server_process.state == RoleProcessState::Active ||
                        client_process.state == RoleProcessState::Active;
    const bool abandoned =
        (setup_process.state == RoleProcessState::Inactive &&
         !setup.protocol_pass && !setup.failed) ||
        (server_process.state == RoleProcessState::Inactive &&
         !server.protocol_pass && !server.failed) ||
        (client_process.state == RoleProcessState::Inactive &&
         !client.protocol_pass && !client.failed);

    std::cout << "Laminate " << command.variant_name << ' '
              << command.profile_name;
    if (command.variant == PackedProcessVariant::Laned) {
        std::cout << " (B=" << command.lanes << ')';
    }
    std::cout << " status\n";
    if (has_setup) {
        std::cout << "  Fiat-Shamir: one transcript, GKR then Spartan packing argument\n"
                  << "  GKR multiplication: h(0) messages and stripped terminal product\n"
                  << "  GKR layer transitions: one claim by selector interpolation\n";
    }
    if (diagnostic_ciphertext_hash) {
        std::cout << "  ciphertext hash: simpleCTHash/v2 (diagnostic; no "
                     "ciphertext-binding or transcript-packing integrity "
                     "claim)\n";
    } else {
        std::cout << "  ciphertext hash: Poseidon (poseidon/v2)\n";
    }
    std::cout
              << "  setup: " << completion_label(setup)
              << "\n  client request: "
              << (regular_file_exists(
                      path("shared/transcript/cli-to-srv-request.bin"))
                      ? "published"
                      : "not published")
              << "\n  server: " << completion_label(server)
              << "\n  server response: "
              << (regular_file_exists(
                      path("shared/transcript/srv-to-cli-response.bin"))
                      ? "published"
                      : "not published")
              << "\n  client proof verification: "
              << (proof_verification_pass
                      ? "PASS"
                      : client.failed ? "FAILED" : "not complete")
              << "\n  post-verification honest payload-output noise audit: ";
    if (output_noise_pass) {
        std::cout << "PASS";
    } else if (output_noise_failed) {
        std::cout << "FAILED";
    } else if (output_noise_diagnostic) {
        std::cout << "complete (diagnostic; target not enforced)";
    } else if (proof_verification_pass && client.failed &&
               output_noise_started) {
        std::cout << "FAILED (use audit_output for "
                     "the exact canonical-error result)";
    } else if (output_noise_started) {
        std::cout << "in progress";
    } else {
        std::cout << "not started";
    }
    std::cout << '\n';
    print_role_status("setup", setup_process, setup.accepted || setup.failed);
    print_role_status("client", client_process,
                      client.accepted || client.failed);
    print_role_status("server", server_process,
                      server.accepted || server.failed);
    print_client_progress(path("client/progress.jsonl"));
    if (client.failed) {
        print_client_failure(path("client/failure.txt"));
    }
    print_server_progress(path("server/progress.jsonl"), server_process);

    if (invalid || setup.failed || server.failed || client.failed ||
        abandoned) {
        std::cout << "\nFAILED OR ABANDONED: inspect the matching failure, "
                     "process-exit, activity, and console files.\n";
        return 1;
    }
    if (setup.accepted && server.accepted && client.accepted) {
        std::cout << "\nCOMPLETE AND ACCEPTED: the separate client verified "
                     "the sole server response.\n";
        return 0;
    }
    if (setup.protocol_pass || server.protocol_pass || client.protocol_pass) {
        std::cout << "\nFINISHING OR INCOMPLETE: final acceptance requires "
                     "all protocol PASS records and zero wrapper exits.\n";
    } else if (active) {
        std::cout << "\nRUNNING OR WAITING: at least one role is active.\n";
    } else {
        std::cout << "\nINCOMPLETE: start the missing role process.\n";
    }
    return 0;
}

} // namespace

#ifdef LAMINATE_PACKED_CAPACITY_TEST
int main(int argc, char **argv) {
    try {
        require(argc == 1 || argc == 4, "packed capacity test expects variant, tier, lanes");
        const auto host = derive_host_resource_budget(8'900'000'000'000ULL,
                                                     372'000'000'000ULL);
        std::size_t cases = 0;
        for (const auto variant : {PackedProcessVariant::Folded, PackedProcessVariant::Laned}) {
            for (const auto tier : {PackedProcessTier::Quick, PackedProcessTier::TargetBalanced,
                                    PackedProcessTier::TargetMulHeavy}) {
                if (variant == PackedProcessVariant::Laned &&
                    tier == PackedProcessTier::TargetMulHeavy) continue;
                for (const std::size_t lanes : {std::size_t{1}, std::size_t{128}, std::size_t{16384}}) {
                    if (variant == PackedProcessVariant::Folded && lanes != 1) continue;
                    const auto variant_name = variant == PackedProcessVariant::Folded ? "folded" : "laned";
                    const auto selected_lanes = variant == PackedProcessVariant::Folded ? 0 : lanes;
                    if (argc == 4 && (std::string_view(argv[1]) != variant_name ||
                        std::string_view(argv[2]) != std::to_string(static_cast<unsigned>(tier)) ||
                        std::string_view(argv[3]) != std::to_string(selected_lanes))) continue;
                    ++cases;
                    std::cout << "CHECK variant=" << variant_name << " tier="
                              << static_cast<unsigned>(tier) << " lanes=" << selected_lanes
                              << std::endl;
                    const auto profile = packed_process_profile(variant, tier, selected_lanes);
                    const auto payload = make_payload_circuit(workload_spec(profile));
                    const auto circuit = compile(payload);
                    const auto scratch_root = std::filesystem::temp_directory_path() /
                        ("laminate-packed-capacity-" + std::string(variant_name) + "-" +
                         std::to_string(static_cast<unsigned>(tier)) + "-" +
                         std::to_string(selected_lanes) + "-" +
                         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
                    require(!std::filesystem::exists(scratch_root), "capacity test scratch already exists");
                    const auto preflight = plan_packed_structural_preflight(profile, payload, circuit, host,
                        scratch_root);
                    require(!std::filesystem::exists(scratch_root), "preflight wrote commitment artifacts");
                    require(preflight.minimum_builder_peak <= host.max_resident_ram_bytes,
                            "packed capacity regression: builder exceeds host");
                    if (variant == PackedProcessVariant::Laned &&
                        tier == PackedProcessTier::TargetBalanced) {
                        const auto check_eager_admission = [&](const PackedStructuralPreflight &admission) {
                            const auto &eager = admission.eager_laned;
                            require(eager.resources.eligible == (lanes == 1),
                                    "target Laned eager-packing eligibility changed");
                            if (lanes != 1) {
                                require(eager.resources.resident_workspace_bytes == 0 &&
                                            eager.peak_resident_bytes == 0 &&
                                            eager.peak_live_scratch_bytes == 0,
                                        "non-eager Laned profile acquired an eager reserve");
                                return;
                            }
                            require(eager.resources.maximum_mask_cache_resident_bytes ==
                                        66'571'993'088ULL,
                                    "target B=1 preflight omitted the full prepared-mask cache");
                            require(eager.resources.maximum_builder_resident_bytes > 0 &&
                                        eager.resources.resident_workspace_bytes >
                                            eager.resources.maximum_mask_cache_resident_bytes,
                                    "target B=1 preflight omitted the eager builder workspace");
                            require(admission.server_resident_floor >=
                                        eager.resources.resident_workspace_bytes &&
                                        eager.peak_resident_bytes >= admission.server_resident_floor &&
                                        eager.peak_resident_bytes <= admission.server_resident_cap,
                                    "target B=1 eager admission exceeds its reserved server RAM");
                            require(eager.peak_live_scratch_bytes > 0 &&
                                        eager.peak_live_scratch_bytes <=
                                            admission.selected_required_available_disk_bytes,
                                    "target B=1 eager disk peak is absent from admission");
                        };
                        check_eager_admission(preflight);
                        if (lanes == 1) {
                            const auto reference_host = derive_host_resource_budget(
                                host.observed_available_disk_bytes, 392'855'961'600ULL);
                            check_eager_admission(plan_packed_structural_preflight(
                                profile, payload, circuit, reference_host, scratch_root));
                            require(!std::filesystem::exists(scratch_root),
                                    "reference-host preflight wrote commitment artifacts");
                        }
                    }
                    const auto constrained = derive_host_resource_budget(host.observed_available_disk_bytes,
                        kBenchmarkOperatingSystemRamReserveBytes + kBenchmarkPageCacheRamReserveBytes + 1);
                    bool rejected = false;
                    try { (void)plan_packed_structural_preflight(profile, payload, circuit, constrained,
                        scratch_root); }
                    catch (const std::exception &) { rejected = true; }
                    require(rejected, "packed capacity regression: constrained RAM was accepted");
                    require(!std::filesystem::exists(scratch_root), "RAM rejection wrote commitment artifacts");
                    if (variant == PackedProcessVariant::Folded && tier != PackedProcessTier::Quick) {
                        require(preflight.replay_work_units == 0,
                                "Folded target admitted a replaying reference plan");
                        const auto low_disk = derive_host_resource_budget(
                            preflight.selected_required_available_disk_bytes - 1,
                            host.observed_physical_ram_bytes);
                        std::string reason;
                        try { (void)plan_packed_structural_preflight(profile, payload, circuit, low_disk,
                            scratch_root); }
                        catch (const std::exception &error) { reason = error.what(); }
                        require(reason.find("target capacity requires payload replay") != std::string::npos,
                                "Folded target must reject insufficient zero-replay disk before commitments");
                        require(reason.find("zero-replay required available disk=") != std::string::npos,
                                "disk rejection omits required available capacity");
                        require(!std::filesystem::exists(scratch_root), "disk rejection wrote commitment artifacts");
                        std::cout << "EXPECTED REJECTION: " << reason << std::endl;
                    }
                    std::cout << "PASS variant=" << variant_name
                              << " tier=" << static_cast<unsigned>(tier) << " lanes=" << selected_lanes
                              << " builder=" << preflight.minimum_builder_peak
                              << " required-available-disk="
                              << preflight.selected_required_available_disk_bytes
                              << " known-common-disk=" << preflight.server_common_disk_floor << std::endl;
                }
            }
        }
        require(cases != 0, "packed capacity test selected no supported profile");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
#else
int main(int argc, char **argv) {
    laminate::bench::configure_process_memory_runtime();
    try {
        if (argc == 2 && std::string_view(argv[1]) == "build_info") {
            return run_build_info();
        }
        const ProcessCommand command = parse_process_command(argc, argv);
        try {
            switch (command.action) {
            case ProcessAction::Setup:
                return run_setup(command, argc, argv);
            case ProcessAction::RunClient:
                return run_client(command, argc, argv);
            case ProcessAction::RunServer:
                return run_server(command, argc, argv);
            case ProcessAction::AuditOutput:
                return audit_existing_output(command, argc, argv);
            case ProcessAction::Status:
                return run_status(command);
            }
        } catch (const std::exception &error) {
            // Status is a read-only observer. A typo in its variant/profile/B
            // must never publish terminal failure evidence into an immutable
            // client or server role.
            if (command.action != ProcessAction::Status &&
                command.action != ProcessAction::AuditOutput) {
                const PackedProcessProfile profile = packed_process_profile(
                    command.variant, command.tier, command.lanes);
                if (profile.admits_execution()) {
                    publish_failure(command, error.what());
                }
            }
            throw;
        }
        throw std::logic_error("unknown packed process action");
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}

#endif
