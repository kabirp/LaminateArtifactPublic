/// @file base_checkpoint_benchmark.cpp
/// @brief Role-separated, real-SEAL Base benchmark driver.
///
/// The artifact runbook uses the setup/run_client/run_server process actions:
/// reusable role preprocessing is published once, then one encrypted request
/// is evaluated and proved with bounded checkpoint replay. The client verifies
/// before releasing outputs. Additional diagnostic entry points in this file
/// have separate purposes and are not the named-profile reproduction flow.

#include "benchmark_support.hpp"
#include "gate_mle_report_policy.hpp"
#include "client_computation.hpp"
#include "base_checkpoint_git_state.hpp"
#include "base_response_noise_audit.hpp"
#include "base_saved_affine_audit.hpp"
#include "completed_result_report.hpp"
#include "protocol_progress.hpp"
#include "run_lifecycle_lock.hpp"
#include "setup_execution.hpp"
#include "target_noise_preflight.hpp"

#include "laminate/delegation/base/client.hpp"
#include "laminate/delegation/base/profiling/client.hpp"
#include "laminate/gkr/detail/base/verification/diagnostic.hpp"
#include "laminate/delegation/base/server.hpp"
#include "laminate/delegation/base/wire/codec.hpp"
#include "laminate/bench/base_pyramid_parameters.hpp"
#include "laminate/bench/host_resource_budget.hpp"
#include "laminate/bench/payload_profile.hpp"
#include "laminate/gates/wide_opening.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/payload/checkpoint/plan.hpp"
#include "laminate/payload/checkpoint/session_engine.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/noise/honest_base_proof_noise.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/protocol/storage/base_preprocessing.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <sched.h>
#endif

#ifndef LAMINATE_GIT_COMMIT
#define LAMINATE_GIT_COMMIT "unknown"
#endif
#ifndef LAMINATE_GIT_DIRTY
#define LAMINATE_GIT_DIRTY "unknown"
#endif
#ifndef LAMINATE_BUILD_TYPE
#define LAMINATE_BUILD_TYPE "unknown"
#endif
#ifndef LAMINATE_COMPILER
#define LAMINATE_COMPILER "unknown"
#endif

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::payload;

namespace {

constexpr std::size_t kDiagnosticDefaultSlots = std::size_t{1} << 14U;
constexpr std::size_t kDiagnosticDefaultDepth = 8;
constexpr std::size_t kDiagnosticDefaultReplayChunkCiphertexts = 64;
constexpr PayloadRecomputationFactorLimit
    kDiagnosticMaximumRecomputationFactor{5, 2};
constexpr std::uint64_t kPayloadStorageTransferResidentBytes =
    3U * kFileTraceStoreTransferBufferBytes;

struct DiagnosticOptions {
    std::size_t slots = kDiagnosticDefaultSlots;
    std::size_t depth = kDiagnosticDefaultDepth;
    std::size_t width = 0;
    std::size_t inputs = 0;
    std::uint64_t seed = 1;
    WorkloadKind workload_kind = WorkloadKind::Diamond;
    std::optional<std::size_t> operation_count;
    std::vector<std::size_t> multiplication_widths;
    std::uint64_t max_live_disk_bytes = 0;
    std::uint64_t max_resident_ram_bytes = 0;
    std::uint64_t min_free_disk_bytes = 0;
    std::uint64_t client_private_persistent_disk_bytes = 0;
    std::size_t max_replay_chunk_ciphertexts =
        kDiagnosticDefaultReplayChunkCiphertexts;
    PayloadCheckpointSelectionObjective checkpoint_selection_objective =
        PayloadCheckpointSelectionObjective::MinimumStorage;
    bool assess_proof_noise = true;
    bool require_zero_payload_replay = false;
};

struct Options {
    std::filesystem::path work_directory;
    DiagnosticOptions diagnostic;
    HostResourceBudget host_budget;
};

void emit_seal_operation_counts(
    const Record &record, std::string_view stage,
    const SealBackend::OperationCounts &counts) {
    const std::string prefix = "operations." + std::string(stage) + '.';
    for (std::size_t index = 0;
         index < static_cast<std::size_t>(
                     SealBackend::OperationKind::Count);
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

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::uint64_t checked_add_u64(std::uint64_t left, std::uint64_t right,
                              std::string_view description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left + right;
}

std::uint64_t checked_multiply_u64(std::uint64_t left,
                                   std::uint64_t right,
                                   std::string_view description) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(description) + " overflows");
    }
    return left * right;
}

std::size_t checked_size(std::uint64_t value,
                         std::string_view description) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(description) +
                                  " does not fit size_t");
    }
    return static_cast<std::size_t>(value);
}

std::string decimal_list(std::span<const std::uint64_t> values) {
    std::string result;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            result.push_back(',');
        }
        result += std::to_string(values[index]);
    }
    return result;
}

std::string index_list(std::span<const std::size_t> values) {
    std::string result;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            result.push_back(',');
        }
        result += std::to_string(values[index]);
    }
    return result.empty() ? "none" : result;
}

class SessionDirectory {
  public:
    SessionDirectory(const std::filesystem::path &parent, bool retain)
        : retain_(retain) {
        std::error_code error;
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(parent, error);
        if (error || std::filesystem::is_symlink(status) ||
            !std::filesystem::is_directory(status)) {
            throw std::invalid_argument(
                "--work-dir must be an existing, non-symlink directory");
        }
        const std::filesystem::path canonical_parent =
            std::filesystem::weakly_canonical(
                std::filesystem::absolute(parent), error);
        if (error || canonical_parent.empty()) {
            throw std::invalid_argument("--work-dir cannot be canonicalized");
        }

        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            root_ = canonical_parent /
                    ("laminate-base-checkpoint-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(root_, error)) {
                try {
                    make_private(root_);
                } catch (...) {
                    std::error_code ignored;
                    std::filesystem::remove_all(root_, ignored);
                    throw;
                }
                return;
            }
            if (error) {
                break;
            }
        }
        throw std::runtime_error("failed to create private session directory");
    }

    ~SessionDirectory() {
        if (!retain_) {
            std::error_code ignored;
            std::filesystem::remove_all(root_, ignored);
        }
    }

    std::filesystem::path make_child(std::string_view name) const {
        const std::filesystem::path child = root_ / name;
        if (!std::filesystem::create_directory(child)) {
            throw std::runtime_error("failed to create private work child");
        }
        try {
            make_private(child);
        } catch (...) {
            std::error_code ignored;
            std::filesystem::remove_all(child, ignored);
            throw;
        }
        return child;
    }

  private:
    static void make_private(const std::filesystem::path &directory) {
        std::error_code error;
        std::filesystem::permissions(
            directory, std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace, error);
        if (error) {
            throw std::runtime_error(
                "failed to make session directory owner-only");
        }
        const std::filesystem::perms actual =
            std::filesystem::status(directory, error).permissions();
        constexpr std::filesystem::perms forbidden =
            std::filesystem::perms::group_all |
            std::filesystem::perms::others_all;
        if (error || (actual & forbidden) != std::filesystem::perms::none) {
            throw std::runtime_error(
                "failed to make session directory owner-only");
        }
    }

    std::filesystem::path root_;
    bool retain_ = false;
};

struct RunProfile {
    PayloadCircuit payload;
    std::vector<SlotVector> inputs;
    SealParameters seal_parameters;
    HonestPayloadNoiseCalibration calibration;
    HonestBaseProofNoiseCalibration base_proof_noise_calibration;
};

WorkloadSpec diagnostic_workload_spec(const DiagnosticOptions &options) {
    WorkloadSpec spec{
        .kind = options.workload_kind,
        .shape = PayloadShape::wide(options.slots),
        .multiplicative_depth = options.depth,
        .width = options.width,
        .seed = options.seed,
    };
    spec.input_count = options.inputs;
    spec.operation_count = options.operation_count;
    spec.multiplication_widths = options.multiplication_widths;
    return spec;
}

Workload make_diagnostic_workload(const DiagnosticOptions &options) {
    WorkloadSpec spec = diagnostic_workload_spec(options);
    Workload workload = make_workload(spec);
    require(workload.circuit.input_count == options.inputs &&
                workload.circuit.outputs.size() ==
                    kBenchmarkDiamondOutputCiphertexts,
            "diagnostic workload geometry drifted");
    return workload;
}

// Explicit chain variants used for current profiles and read-only compatibility.
enum class BaseSealParameterVersion {
    Current,
    TenDataPrimes,
    ElevenDataPrimes,
};

SealParameters diagnostic_seal_parameters(
    std::size_t slots, WorkloadKind workload_kind, bool generate_galois_keys,
    BaseSealParameterVersion version = BaseSealParameterVersion::Current) {
    switch (version) {
    case BaseSealParameterVersion::Current:
    case BaseSealParameterVersion::TenDataPrimes:
    case BaseSealParameterVersion::ElevenDataPrimes:
        break;
    default:
        throw std::invalid_argument("unknown Base SEAL parameter version");
    }
    // Small limbs permit a cheap modulus switch after each multiplicative
    // level. Every prime is 1 modulo lcm(2N, t) for N <= 2^14.
    SealParameters parameters{
        .poly_modulus_degree = slots,
        // Base diagnostic chain; exact compatibility variants are selected below.
        // See docs/PRIVACY_ESTIMATES.md for key-modulus estimates.
        .fresh_rns_limbs = 10,
        .exact_data_primes =
            {1'053'858'393'162'252'289ULL,
             15'032'614'913ULL,
             53'687'910'401ULL,
             96'638'238'721ULL,
             98'785'755'137ULL,
             118'113'402'881ULL,
             122'408'435'713ULL,
             246'964'387'841ULL,
             272'734'584'833ULL,
             292'062'232'577ULL},
        .exact_special_prime = 8'590'163'969ULL,
        .special_prime_bits = 34,
        .security_level = seal::sec_level_type::none,
        .max_fresh_ciphertext_modulus_bits = 392,
        .max_key_modulus_bits = 426,
        .generate_galois_keys = generate_galois_keys,
    };
    if (version != BaseSealParameterVersion::TenDataPrimes) {
        parameters.exact_data_primes.push_back(1'095'233'372'161ULL);
        ++parameters.fresh_rns_limbs;
        parameters.max_fresh_ciphertext_modulus_bits += 40;
        parameters.max_key_modulus_bits += 40;
    }
    if (version == BaseSealParameterVersion::Current &&
        workload_kind == WorkloadKind::MulHeavyPyramid) {
        // The pyramid uses a three-limb proof suffix and eight payload heads.
        // Its exact chain is defined in base_pyramid_parameters.hpp.
        parameters.exact_data_primes.assign(kBasePyramidDataPrimes.begin(),
                                           kBasePyramidDataPrimes.end());
        parameters.exact_special_prime = kBasePyramidSpecialPrime;
        parameters.special_prime_bits = 60;
        parameters.max_fresh_ciphertext_modulus_bits = kBasePyramidDataModulusBits;
        parameters.max_key_modulus_bits = kBasePyramidKeyModulusBits;
    }
    return parameters;
}

HonestPayloadNoiseCalibration diagnostic_payload_calibration() {
    // Fixed operation debits are empirical engineering inputs, not bounds on
    // arbitrary deep BGV operands. Model acceptance does not establish a
    // calibrated failure probability or end-to-end completeness; real-SEAL
    // preflight checks exercise the selected chain on bounded target cones.
    constexpr std::uint64_t switch_events = 16'000'000;
    constexpr std::size_t switch_failure_bits = 110;
    return HonestPayloadNoiseCalibration{
        .fresh_canonical_error_bound = 59'904,
        .ctct_relinearized_debit_bits = 36,
        .plaintext_multiplication_debit_bits = 24,
        .rotation_debit_bits = 34,
        .maximum_switch_tax_bits = 10,
        // Derive the rounding allowance from the complete event inventory,
        // including proof-snapshot switches.
        .switch_rounding_error_bound = randomized_mod_switch_rounding_heuristic_bound(
            kDefaultPolyModulusDegree, switch_events, switch_failure_bits),
        .modeled_switch_events_upper_bound = switch_events,
        .switch_model_failure_budget_bits = switch_failure_bits,
        // The committed Base policy overrides this diagnostic seed with its
        // fixed three-limb payload reserve; offline selectors choose the reserve.
        .proof_suffix_level_reserve = 0,
    };
}

HonestBaseProofNoiseCalibration diagnostic_base_proof_calibration() {
    return HonestBaseProofNoiseCalibration{
        .ctct_relinearized_debit_bits = 36,
        // Base proof masks are full-slot F_q plaintexts. Charge the field
        // coefficient, the worst-case N-slot accumulation, and eight bits of
        // diagnostic headroom.
        .plaintext_multiplication_debit_bits =
            std::bit_width(kBaseFieldOrder - 1U) +
            std::bit_width(kDefaultPolyModulusDegree - 1U) + 8U,
        .rotation_debit_bits = 0,
    };
}

RunProfile make_run_profile(const Options &options,
                            bool construct_plaintext_inputs = true) {
    PayloadCircuit payload;
    std::vector<SlotVector> inputs;
    if (construct_plaintext_inputs) {
        Workload workload = make_diagnostic_workload(options.diagnostic);
        payload = std::move(workload.circuit);
        inputs = std::move(workload.inputs);
    } else {
        payload = make_payload_circuit(
            diagnostic_workload_spec(options.diagnostic));
        require(payload.input_count == options.diagnostic.inputs &&
                    payload.outputs.size() ==
                        kBenchmarkDiamondOutputCiphertexts,
                "diagnostic workload geometry drifted");
    }
    // The Base proof and checkpoint/replay paths introduce no rotations, so
    // only explicit payload Rotate gates require Galois keys.
    const bool generate_galois_keys = std::any_of(
        payload.gates.begin(), payload.gates.end(),
        [](const Gate &gate) { return gate.op == GateOp::Rotate; });
    return RunProfile{
        .payload = std::move(payload),
        .inputs = std::move(inputs),
        .seal_parameters = diagnostic_seal_parameters(
            options.diagnostic.slots, options.diagnostic.workload_kind,
            generate_galois_keys),
        .calibration = diagnostic_payload_calibration(),
        .base_proof_noise_calibration =
            diagnostic_base_proof_calibration(),
    };
}

struct ReplayResourceBounds {
    std::vector<std::uint64_t> serialized_ciphertext_bytes_by_rns_limb;
    std::vector<std::uint64_t> resident_ciphertext_bytes_by_rns_limb;
    std::uint64_t checkpoint_set_fixed_bytes = 0;
    std::uint64_t checkpoint_set_bytes_per_layer = 0;
    bool prefer_post_modulus_switch_checkpoint = false;
};

ReplayResourceBounds diagnostic_replay_resource_bounds(
    std::size_t slots, std::size_t fresh_rns_limbs) {
    ReplayResourceBounds result;
    result.serialized_ciphertext_bytes_by_rns_limb.reserve(fresh_rns_limbs);
    result.resident_ciphertext_bytes_by_rns_limb.reserve(fresh_rns_limbs);
    for (std::size_t limbs = 1; limbs <= fresh_rns_limbs; ++limbs) {
        const std::uint64_t raw_coefficients = checked_multiply_u64(
            checked_multiply_u64(2, slots,
                                 "diagnostic ciphertext coefficient count"),
            checked_multiply_u64(limbs, sizeof(std::uint64_t),
                                 "diagnostic ciphertext limb bytes"),
            "diagnostic ciphertext coefficient bytes");
        result.serialized_ciphertext_bytes_by_rns_limb.push_back(
            checked_add_u64(raw_coefficients, std::uint64_t{1} << 16U,
                            "diagnostic serialized ciphertext bound"));
        result.resident_ciphertext_bytes_by_rns_limb.push_back(
            checked_add_u64(raw_coefficients, std::uint64_t{1} << 17U,
                            "diagnostic resident ciphertext bound"));
    }
    result.checkpoint_set_fixed_bytes = 159;
    result.checkpoint_set_bytes_per_layer = 8;
    result.prefer_post_modulus_switch_checkpoint = true;
    return result;
}

PayloadCheckpointReplayProblem make_replay_problem(
    const CertifiedCanonicalTraceLayout &certified_trace_layout,
    const FheEvaluationPlan &evaluation,
    const ReplayResourceBounds &bounds) {
    const LayeredCircuit &circuit = certified_trace_layout.circuit();
    const CanonicalTraceLayout &trace_layout =
        certified_trace_layout.layout();
    if (bounds.serialized_ciphertext_bytes_by_rns_limb.empty() ||
        bounds.resident_ciphertext_bytes_by_rns_limb.size() !=
            bounds.serialized_ciphertext_bytes_by_rns_limb.size()) {
        throw std::invalid_argument(
            "replay resource bounds must cover matching RNS levels");
    }
    const std::vector<std::uint64_t> work =
        payload_replay_work_units(certified_trace_layout);
    const std::vector<LayerStorageLayout> &storage = trace_layout.storage;
    std::vector<PayloadLayerResourceEstimate> resources;
    resources.reserve(circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const std::size_t limbs =
            evaluation.trace.required_mult_depth_by_layer[layer] + 1U;
        const std::uint64_t layer_serialized =
            bounds.serialized_ciphertext_bytes_by_rns_limb.at(limbs - 1U);
        const std::uint64_t layer_resident =
            bounds.resident_ciphertext_bytes_by_rns_limb.at(limbs - 1U);
        const std::size_t ingress_limbs =
            evaluation.proof_ingress_mult_depth_by_layer[layer] + 1U;
        const std::uint64_t ingress_serialized =
            bounds.serialized_ciphertext_bytes_by_rns_limb.at(
                ingress_limbs - 1U);
        const std::uint64_t ingress_resident =
            bounds.resident_ciphertext_bytes_by_rns_limb.at(
                ingress_limbs - 1U);
        resources.push_back(PayloadLayerResourceEstimate{
            .rns_limb_count = limbs,
            .checkpoint_bytes = standalone_checkpoint_layer_artifact_bytes(
                storage[layer].stored_wire_count, layer_serialized),
            .serialized_ciphertext_bytes = layer_serialized,
            .resident_ciphertext_bytes = layer_resident,
            .replay_work_units = work[layer],
            .prefer_post_modulus_switch_checkpoint =
                bounds.prefer_post_modulus_switch_checkpoint &&
                evaluation.modulus_switches_after_layer[layer] != 0,
            .proof_ingress_serialized_ciphertext_bytes =
                ingress_serialized,
            .proof_ingress_resident_ciphertext_bytes = ingress_resident,
        });
    }
    return make_payload_checkpoint_replay_problem(
        certified_trace_layout, evaluation, resources,
        bounds.checkpoint_set_fixed_bytes,
        bounds.checkpoint_set_bytes_per_layer);
}

protocol::BaseProverOptions make_proof_options(
    const LayeredCircuit &circuit, const SessionDirectory &session,
    const FileTraceStoreOptions &scratch_limits,
    std::uint64_t multiplication_sort_buffer_payload_bytes) {
    protocol::BaseProverOptions result;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size();
         ++layer) {
        if (layer_kind(circuit.layers[layer]) ==
            LayerKind::Multiplication) {
            result.multiplication_scratch.push_back(
                gkr::base_detail::FileBaseMultiplicationScratch{
                    layer,
                    session.make_child("gkr-multiplication-" +
                                       std::to_string(layer)),
                    scratch_limits,
                    multiplication_sort_buffer_payload_bytes});
        }
    }
    return result;
}

struct DirectBaseWireRequirements {
    std::size_t claim_coordinates = 0;
    std::size_t max_ciphertexts_per_message = 0;
    std::size_t max_ciphertext_bytes = 0;
    std::size_t max_total_ciphertext_bytes_per_message = 0;
    std::size_t reductions = 0;
    std::size_t rounds_per_reduction = 0;
    std::size_t partial_gate_values = 0;
    std::size_t total_field_elements = 0;
    std::size_t proof_bytes = 0;
    std::size_t proof_response_bytes = 0;
    std::size_t message_bytes = 0;
    std::uint64_t input_resident_bytes = 0;
    std::uint64_t output_resident_bytes = 0;
    std::uint64_t proof_resident_bytes = 0;
    std::uint64_t proof_encoding_bytes = 0;
    std::uint64_t proof_framing_bytes = 0;
};

struct DirectBaseWireGeometry {
    std::size_t claim_coordinates = 0;
    std::size_t input_ciphertexts = 0;
    std::size_t output_ciphertexts = 0;
    std::size_t proof_ciphertexts = 0;
    std::size_t proof_extension_ciphertexts = 0;
    std::size_t reductions = 0;
    std::size_t logical_round_messages = 0;
    std::size_t rounds_per_reduction = 0;
    std::size_t partial_gate_values = 0;
    std::size_t partial_gate_field_elements = 0;
    std::size_t total_field_elements = 0;
};

DirectBaseWireGeometry direct_base_wire_geometry(
    const HonestBaseProofNormalizationPlan &normalization_plan,
    const CertifiedCanonicalTraceLayout &certified_trace_layout) {
    const LayeredCircuit &circuit = certified_trace_layout.circuit();
    const CanonicalTraceLayout &trace_layout =
        certified_trace_layout.layout();
    if (circuit.shape.kind != PayloadKind::Wide ||
        circuit.layers.size() < 2U ||
        normalization_plan.reductions.size() + 1U !=
            circuit.layers.size() ||
        trace_layout.wire_support.size() != circuit.layers.size()) {
        throw std::logic_error(
            "direct Base wire geometry disagrees with the certified "
            "schedule or canonical trace layout");
    }

    const std::size_t claim_coordinates =
        gkr::base_detail::layer_vars(circuit, 0);
    std::uint64_t proof_ciphertext_count = 0;
    std::uint64_t proof_extension_count = 0;
    std::uint64_t logical_round_messages = 0;
    std::uint64_t partial_field_elements = 0;
    std::size_t maximum_rounds = 0;
    for (std::size_t layer = 0;
         layer < normalization_plan.reductions.size(); ++layer) {
        const HonestBaseProofNormalizationLayerPlan &reduction =
            normalization_plan.reductions[layer];
        const LayerKind kind = layer_kind(circuit.layers[layer]);
        if (reduction.reduction_layer != layer ||
            reduction.kind != kind) {
            throw std::logic_error(
                "direct Base wire geometry disagrees with the certified "
                "reduction order");
        }
        const std::size_t rounds = reduction.wire_variables;
        maximum_rounds = std::max(maximum_rounds, rounds);
        logical_round_messages = checked_add_u64(
            logical_round_messages, rounds,
            "direct Base logical round-message count");
        const std::uint64_t extension_count = checked_add_u64(
            reduction.round_extension_ciphertext_count,
            reduction.terminal_extension_ciphertext_count,
            "direct Base extension-ciphertext count");
        proof_extension_count = checked_add_u64(
            proof_extension_count, extension_count,
            "direct Base proof extension count");
        proof_ciphertext_count = checked_add_u64(
            proof_ciphertext_count,
            reduction.base_ciphertext_count,
            "direct Base proof ciphertext count");
        if (kind == LayerKind::Affine) {
            partial_field_elements = checked_add_u64(
                partial_field_elements, circuit.shape.value_width(),
                "direct Base partial GateMLE fields");
        }
    }
    return DirectBaseWireGeometry{
        .claim_coordinates = claim_coordinates,
        .input_ciphertexts = circuit.payload_input_count,
        .output_ciphertexts =
            trace_layout.wire_support.front().live_wire_count,
        .proof_ciphertexts = checked_size(
            proof_ciphertext_count,
            "direct Base proof ciphertext count"),
        .proof_extension_ciphertexts = checked_size(
            proof_extension_count,
            "direct Base proof extension-ciphertext count"),
        .reductions = normalization_plan.reductions.size(),
        .logical_round_messages = checked_size(
            logical_round_messages,
            "direct Base logical round-message count"),
        .rounds_per_reduction = maximum_rounds,
        .partial_gate_values = circuit.shape.value_width(),
        .partial_gate_field_elements = checked_size(
            partial_field_elements,
            "direct Base partial GateMLE field count"),
        .total_field_elements = checked_size(
            partial_field_elements, "direct Base field-element count"),
    };
}

template <typename Value>
std::string target_layer_values(const LayeredCircuit &circuit,
                                Value &&value) {
    std::string result;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        if (layer != 0) {
            result.push_back(',');
        }
        result += std::to_string(value(layer));
    }
    return result;
}

DirectBaseWireRequirements direct_base_wire_requirements(
    const CertifiedHonestPayloadSchedule &certified_schedule,
    const CertifiedCanonicalTraceLayout &trace_layout,
    std::span<const std::uint64_t> serialized_by_rns_limb,
    std::span<const std::uint64_t> resident_by_rns_limb) {
    const LayeredCircuit &circuit = trace_layout.circuit();
    const HonestPayloadNoiseSchedule &schedule =
        certified_schedule.schedule();
    if (schedule.base_proof_normalization_plan.reductions.size() + 1U !=
            circuit.layers.size() ||
        circuit.shape.kind != PayloadKind::Wide) {
        throw std::logic_error(
            "target direct-Base wire geometry disagrees with schedule");
    }
    if (serialized_by_rns_limb.size() !=
            schedule.data_moduli_low_to_high.size() ||
        resident_by_rns_limb.size() != serialized_by_rns_limb.size()) {
        throw std::invalid_argument(
            "direct Base wire bounds do not cover every RNS level");
    }
    const DirectBaseWireGeometry geometry =
        direct_base_wire_geometry(
            schedule.base_proof_normalization_plan,
            trace_layout);

    const std::uint64_t fresh_serialized =
        serialized_by_rns_limb.back();
    const std::uint64_t fresh_resident = resident_by_rns_limb.back();
    const std::size_t output_limbs =
        schedule.evaluation_plan.trace.required_mult_depth_by_layer.front() +
        1U;
    const std::uint64_t output_serialized =
        serialized_by_rns_limb[output_limbs - 1U];
    const std::uint64_t output_resident =
        resident_by_rns_limb[output_limbs - 1U];
    const std::uint64_t proof_serialized = serialized_by_rns_limb.front();
    const std::uint64_t proof_resident = resident_by_rns_limb.front();

    const std::uint64_t proof_ciphertext_count =
        geometry.proof_ciphertexts;
    const std::uint64_t proof_extension_count =
        geometry.proof_extension_ciphertexts;
    const std::uint64_t partial_field_elements =
        geometry.partial_gate_field_elements;

    const std::uint64_t request_ciphertext_bytes = checked_multiply_u64(
        geometry.input_ciphertexts, fresh_serialized,
        "target evaluation-request ciphertext bytes");
    const std::uint64_t proof_ciphertext_bytes = checked_multiply_u64(
        proof_ciphertext_count, proof_serialized,
        "target proof ciphertext bytes");
    const std::uint64_t output_ciphertext_bytes = checked_multiply_u64(
        geometry.output_ciphertexts, output_serialized,
        "target evaluation-response ciphertext bytes");
    const base_wire_detail::BaseWireCiphertextBudget ciphertext_budget =
        base_wire_detail::derive_ciphertext_budget(
            {geometry.input_ciphertexts,
             checked_size(request_ciphertext_bytes,
                          "target evaluation-request ciphertext bytes")},
            {geometry.output_ciphertexts,
             checked_size(output_ciphertext_bytes,
                          "target evaluation-response ciphertext bytes")},
            {checked_size(proof_ciphertext_count,
                          "target proof ciphertext count"),
             checked_size(proof_ciphertext_bytes,
                          "target proof ciphertext bytes")});

    const gkr::ProofHeader header{
        gkr::kEncryptedBaseProofVersion,
        {gkr::ProtocolVariant::LaminateBase, GateMleProfile::Direct,
         gkr::CrossRoundPacking::None},
        TraceProvenance::FheEvaluated,
        {},
        {},
        {},
        circuit.layers.size()};
    const std::uint64_t header_bytes =
        gkr::encode_canonical(header).size();
    std::uint64_t proof_transport_bytes = checked_add_u64(
        8, base_wire_detail::kBaseProofTransportDomain.size(),
        "direct Base proof transport label");
    proof_transport_bytes = checked_add_u64(
        proof_transport_bytes,
        checked_add_u64(8, header_bytes, "direct Base proof header"),
        "direct Base proof transport");
    proof_transport_bytes = checked_add_u64(
        proof_transport_bytes, 8, "direct Base reduction count");
    const std::uint64_t extension_framing_bytes = checked_add_u64(
        // Each extension writes its fixed degree (u64) and one presence mask.
        checked_multiply_u64(proof_extension_count, 9,
                             "direct Base extension framing"),
        checked_multiply_u64(proof_ciphertext_count, 8,
                             "direct Base ciphertext framing"),
        "direct Base extension framing");
    proof_transport_bytes = checked_add_u64(
        proof_transport_bytes,
        checked_add_u64(extension_framing_bytes,
                        proof_ciphertext_bytes,
                        "direct Base encrypted proof bytes"),
        "direct Base proof transport");
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        proof_transport_bytes = checked_add_u64(
            proof_transport_bytes, 9,
            "direct Base reduction kind and round count");
        if (layer_kind(circuit.layers[layer]) == LayerKind::Affine) {
            proof_transport_bytes = checked_add_u64(
                proof_transport_bytes,
                checked_add_u64(
                    8,
                    checked_multiply_u64(circuit.shape.value_width(),
                                         kSerializedFpkBytes,
                                         "direct Base partial GateMLE bytes"),
                    "direct Base partial GateMLE bytes"),
                "direct Base proof transport");
        }
    }
    proof_transport_bytes = checked_add_u64(
        proof_transport_bytes, 1,
        "direct Base absent GateMLE-opening flag");
    const std::uint64_t minimum_serialized_field_bytes =
        std::min<std::uint64_t>(kSerializedFpBytes,
                                kSerializedFpkBytes);
    const std::size_t decoded_field_element_limit = checked_size(
        proof_transport_bytes / minimum_serialized_field_bytes,
        "direct Base decoded field-element limit");
    require(decoded_field_element_limit >= geometry.total_field_elements,
            "direct Base proof byte bound does not cover its fields");

    constexpr std::uint64_t bindings_bytes = 4U * Digest{}.size();
    const std::uint64_t request_message_bytes = checked_add_u64(
        kBaseDelegationWireHeaderBytes,
        checked_add_u64(
            checked_add_u64(bindings_bytes + Digest{}.size() + 8U,
                            request_ciphertext_bytes,
                            "target evaluation-request body"),
            checked_multiply_u64(geometry.input_ciphertexts, 8,
                                 "target evaluation-request framing"),
            "target evaluation-request body"),
        "target evaluation-request message");
    const std::uint64_t output_value_bytes = checked_add_u64(
        output_ciphertext_bytes,
        checked_multiply_u64(
            geometry.output_ciphertexts, 9,
            "Base response encrypted-value framing"),
        "Base response encrypted values");
    const std::uint64_t response_message_bytes = checked_add_u64(
        kBaseDelegationWireHeaderBytes,
        checked_add_u64(
            bindings_bytes,
            checked_add_u64(
                4U * sizeof(std::uint64_t) + Digest{}.size() +
                    sizeof(std::uint64_t),
                checked_add_u64(
                    output_value_bytes,
                    checked_add_u64(sizeof(std::uint64_t),
                                    proof_transport_bytes,
                                    "Base response proof"),
                    "Base response output and proof"),
                "Base response statement and proof"),
            "Base response body"),
        "Base response message");
    return DirectBaseWireRequirements{
        .claim_coordinates = geometry.claim_coordinates,
        .max_ciphertexts_per_message =
            ciphertext_budget.max_count_per_message,
        .max_ciphertext_bytes = checked_size(
            fresh_serialized, "direct Base ciphertext bytes"),
        .max_total_ciphertext_bytes_per_message =
            ciphertext_budget.max_bytes_per_message,
        .reductions = geometry.reductions,
        .rounds_per_reduction = geometry.rounds_per_reduction,
        .partial_gate_values = geometry.partial_gate_values,
        // Mixed proof extensions may contain public slot vectors instead of
        // ciphertexts. Every decoded field consumes at least this proof
        // transport budget, which therefore covers either representation.
        .total_field_elements = decoded_field_element_limit,
        .proof_bytes = checked_size(proof_transport_bytes,
                                    "direct Base proof bytes"),
        .proof_response_bytes = checked_size(
            response_message_bytes, "direct Base response bytes"),
        .message_bytes = checked_size(
            std::max(request_message_bytes, response_message_bytes),
            "direct Base message bytes"),
        .input_resident_bytes = checked_multiply_u64(
            geometry.input_ciphertexts, fresh_resident,
            "target resident encrypted input request"),
        .output_resident_bytes = checked_multiply_u64(
            geometry.output_ciphertexts, output_resident,
            "target resident encrypted output response"),
        .proof_resident_bytes = checked_add_u64(
            checked_multiply_u64(proof_ciphertext_count, proof_resident,
                                 "target resident direct Base ciphertexts"),
            checked_multiply_u64(partial_field_elements, sizeof(Fpk),
                                 "target resident partial GateMLEs"),
            "target resident direct Base proof"),
        .proof_encoding_bytes = proof_transport_bytes,
        .proof_framing_bytes = response_message_bytes,
    };
}

void bind_direct_multiplication_capacity_to_circuit(
    const CertifiedCanonicalTraceLayout &certified_trace_layout,
    const PayloadCheckpointReplayProblem &problem,
    protocol::BaseServerCapacityComponents &components,
    bool require_declared_floor = true) {
    const LayeredCircuit &circuit = certified_trace_layout.circuit();
    const CanonicalTraceLayout &trace_layout =
        certified_trace_layout.layout();
    const std::vector<LayerWireSupport> &wire_support =
        trace_layout.wire_support;
    const std::vector<LayerStorageLayout> &storage =
        trace_layout.storage;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) != LayerKind::Multiplication) {
            continue;
        }
        const LayerWireSupport &source_support = wire_support.at(layer + 1U);
        const LayerStorageLayout &source_storage = storage.at(layer + 1U);
        const gkr::detail::DenseMultiplicationAliasPlan aliases =
            gkr::detail::make_dense_multiplication_alias_plan(
                circuit, layer, source_support, source_storage);
        const std::uint64_t builder_floor =
            base_server_detail::minimum_dense_multiplication_builder_ram(
                source_support, source_storage,
                problem.layers.at(layer + 1U), aliases);
        const auto &source = problem.layers.at(layer + 1U);
        const std::uint64_t resident =
            source.proof_ingress_resident_ciphertext_bytes != 0
                ? source.proof_ingress_resident_ciphertext_bytes
                : source.resident_ciphertext_bytes;
        const std::uint64_t serialized =
            source.proof_ingress_serialized_ciphertext_bytes != 0
                ? source.proof_ingress_serialized_ciphertext_bytes
                : source.serialized_ciphertext_bytes;
        const std::uint64_t reduction_floor =
            gkr::detail::dense_multiplication_reduction_workspace_bytes(
                aliases, std::max(resident, checked_add_u64(
                    serialized, 1U, "tagged multiplication source record")),
                layer_dimensions(circuit.layers[layer]).padded_size);
        if (require_declared_floor &&
            (components.multiplication_builder_workspace
                     .resident_ram_bytes < builder_floor ||
             components.multiplication_reduction_workspace
                     .resident_ram_bytes < reduction_floor)) {
            throw std::invalid_argument(
                "target multiplication workspace declarations are below "
                "the circuit-derived metadata floors");
        }
        components.multiplication_builder_workspace.resident_ram_bytes =
            std::max(components.multiplication_builder_workspace
                         .resident_ram_bytes,
                     builder_floor);
        components.multiplication_reduction_workspace.resident_ram_bytes =
            std::max(components.multiplication_reduction_workspace
                         .resident_ram_bytes,
                     reduction_floor);
    }
}

std::uint64_t diagnostic_scaled_bytes(
    std::size_t slots, std::uint64_t full_size_bytes,
    std::uint64_t minimum_bytes, std::string_view description) {
    const std::uint64_t scaled = checked_multiply_u64(
        full_size_bytes, slots, description) /
        kDiagnosticDefaultSlots;
    return std::max(minimum_bytes, scaled);
}

std::uint64_t base_client_preprocessing_bytes_upper(std::size_t slots) {
    return diagnostic_scaled_bytes(
        slots, std::uint64_t{2} << 30U, std::uint64_t{1} << 28U,
        "Base client preprocessing upper");
}

std::uint64_t base_client_peak_resident_bytes_upper(
    std::size_t slots, std::size_t input_count,
    std::uint64_t client_preprocessing_bytes,
    const DirectBaseWireRequirements &wire) {
    const std::uint64_t plaintext_inputs = checked_multiply_u64(
        checked_multiply_u64(slots, input_count,
                             "Base client plaintext input cells"),
        sizeof(Fp), "Base client plaintext input bytes");
    const std::uint64_t restored_preprocessing = checked_multiply_u64(
        2, client_preprocessing_bytes,
        "Base restored client preprocessing reserve");
    const std::uint64_t request_peak = checked_add_u64(
        checked_multiply_u64(2, wire.input_resident_bytes,
                             "Base client encrypted request reserve"),
        wire.message_bytes, "Base client request codec reserve");
    const std::uint64_t response_peak = checked_add_u64(
        checked_multiply_u64(2, wire.message_bytes,
                             "Base client response codec reserve"),
        checked_add_u64(wire.output_resident_bytes,
                        wire.proof_resident_bytes,
                        "Base client decoded response reserve"),
        "Base client response peak reserve");
    return checked_add_u64(
        checked_add_u64(restored_preprocessing, plaintext_inputs,
                        "Base client static resident reserve"),
        checked_add_u64(std::max(request_peak, response_peak),
                        std::uint64_t{2} << 30U,
                        "Base client codec and slack reserve"),
        "Base client peak resident reserve");
}

std::uint64_t diagnostic_compact_metadata_upper(
    const PayloadCheckpointReplayProblem &problem) {
    std::uint64_t all_records = 0;
    std::uint64_t largest = 0;
    std::uint64_t second_largest = 0;
    for (const PayloadReplayLayer &layer : problem.layers) {
        const std::uint64_t records = layer.stored_value_count;
        all_records = checked_add_u64(
            all_records, records,
            "diagnostic compact replay record upper");
        if (records >= largest) {
            second_largest = largest;
            largest = records;
        } else if (records > second_largest) {
            second_largest = records;
        }
    }
    const std::uint64_t charged_records = checked_add_u64(
        all_records,
        checked_add_u64(largest, second_largest,
                        "diagnostic transient record upper"),
        "diagnostic compact replay record upper");
    return checked_multiply_u64(
        charged_records, sizeof(std::uint64_t) + sizeof(Digest),
        "diagnostic compact replay metadata upper");
}

gkr::detail::FileDenseMultiplicationSourceDiskBounds
diagnostic_multiplication_disk_bounds(
    const CertifiedCanonicalTraceLayout &certified_trace_layout,
    const PayloadCheckpointReplayProblem &problem) {
    const LayeredCircuit &circuit = certified_trace_layout.circuit();
    const CanonicalTraceLayout &trace_layout =
        certified_trace_layout.layout();
    gkr::detail::FileDenseMultiplicationSourceDiskBounds result;
    const std::vector<LayerWireSupport> &wire_support =
        trace_layout.wire_support;
    const std::vector<LayerStorageLayout> &storage =
        trace_layout.storage;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) != LayerKind::Multiplication) {
            continue;
        }
        const gkr::detail::DenseMultiplicationAliasPlan aliases =
            gkr::detail::make_dense_multiplication_alias_plan(
                circuit, layer, wire_support.at(layer + 1U),
                storage.at(layer + 1U));
        const PayloadReplayLayer &source = problem.layers.at(layer + 1U);
        const std::uint64_t serialized =
            source.proof_ingress_serialized_ciphertext_bytes == 0
                ? source.serialized_ciphertext_bytes
                : source.proof_ingress_serialized_ciphertext_bytes;
        const auto layer_bounds =
            gkr::detail::file_dense_multiplication_source_disk_bounds(
                aliases.operands.size(), serialized,
                true);
        result.completed_artifact_bytes = std::max(
            result.completed_artifact_bytes,
            layer_bounds.completed_artifact_bytes);
        result.build_peak_bytes = std::max(
            result.build_peak_bytes, layer_bounds.build_peak_bytes);
    }
    require(result.completed_artifact_bytes != 0 &&
                result.build_peak_bytes != 0,
            "diagnostic Diamond unexpectedly has no multiplication scratch");
    return result;
}

BaseWireDecodeLimits diagnostic_wire_limits(
    const DirectBaseWireRequirements &required,
    const LayeredCircuit &circuit,
    const std::optional<gates::GateTableVerifierKey> &gate_key) {
    std::size_t gate_claims = 0;
    std::size_t sparse_claims = 0;
    for (std::size_t layer = 0; layer + 1U < circuit.layers.size(); ++layer) {
        if (layer_kind(circuit.layers[layer]) == LayerKind::Affine) {
            constexpr std::size_t carried_claims = 1U;
            gate_claims += 2U * carried_claims;
            sparse_claims += 3U * carried_claims;

        }
    }
    if (!gate_key) {
        gate_claims = 0;
        sparse_claims = 0;
    }
    std::size_t maximum_path_digests = 0;
    std::size_t maximum_gate_proof_rounds = 0;
    if (gate_key) {
        for (std::size_t selector = 0; selector < gate_key->tables.size();
             ++selector) {
            const gates::SparseTableCommitment &table =
                gate_key->tables[selector];
            const gates::GateTableDescriptor &descriptor =
                gate_key->layout.tables.at(selector);
            const std::size_t entry_variables =
                basefold::log2_exact(table.message_size);
            const std::size_t product_layers = basefold::log2_exact(
                std::bit_ceil(descriptor.local_variables + 1U));
            const std::size_t maximum_product_rounds =
                product_layers == 0
                    ? entry_variables
                    : entry_variables + product_layers - 1U;
            maximum_gate_proof_rounds = std::max(
                {maximum_gate_proof_rounds,
                 descriptor.local_variables,
                 entry_variables,
                 product_layers,
                 maximum_product_rounds});
            const std::size_t codeword_rows = checked_size(
                checked_multiply_u64(
                    table.shard_size,
                    std::uint64_t{1}
                        << gate_key->basefold_parameters.log_rate,
                    "structured GateMLE codeword rows"),
                "structured GateMLE codeword rows");
            maximum_path_digests = std::max(
                maximum_path_digests,
                static_cast<std::size_t>(
                    std::bit_width(codeword_rows) - 1U));
        }
    }
    if (gate_key && gate_key->layout.table_set == gates::GateTableSet::Wide) {
        sparse_claims = 24U * std::max<std::size_t>(1, gate_key->layout.wide_layers.size());
        std::vector<std::size_t> sizes;
        for (const auto &layer : gate_key->layout.wide_layers)
            sizes.push_back(layer.node_count ? layer.dimensions.internal_scalars : 0);
        const auto include_message = [&](std::size_t cells) {
            const auto m = basefold::log2_exact(cells);
            maximum_gate_proof_rounds = std::max(maximum_gate_proof_rounds, m);
            maximum_path_digests = std::max(maximum_path_digests,
                m + basefold::foldable::kLogRate);
        };
        for (const auto &group : gates::wide_adjoint_group_layout(sizes))
            include_message(group.message_size);
        if (gate_key->wide_public_commitment)
            include_message(gate_key->wide_public_commitment->m);
    }
    const std::size_t gate_target_values = gate_key
        ? base_wire_detail::gate_target_values_upper_bound(
              *gate_key, sparse_claims)
        : 0U;
    return BaseWireDecodeLimits{
        .max_message_bytes = required.message_bytes,
        .max_ciphertexts = required.max_ciphertexts_per_message,
        .max_ciphertext_bytes = required.max_ciphertext_bytes,
        .max_total_ciphertext_bytes =
            required.max_total_ciphertext_bytes_per_message,
        .max_claim_coordinates = required.claim_coordinates,
        .max_proof_bytes = required.proof_bytes,
        .max_reductions = required.reductions,
        .max_rounds_per_reduction = required.rounds_per_reduction,
        .max_gate_proof_rounds = maximum_gate_proof_rounds,
        .max_partial_gate_values = required.partial_gate_values,
        .max_gate_claims = gate_claims,
        .max_gate_target_values = gate_target_values,
        .max_basefold_queries = gate_key
            ? std::max(gate_key->basefold_parameters.num_queries,
                       gate_key->foldable_parameters.num_queries) : 0U,
        .max_merkle_path_digests = maximum_path_digests,
        .max_total_field_elements = required.total_field_elements,
        .max_total_digests = gate_key
            ? checked_size(gate_mle_prover_resource_bounds(*gate_key)
                               .proof_bytes_upper_bound /
                               basefold::Digest{}.size(),
                           "structured GateMLE digest budget")
            : 0U,
    };
}

void add_structured_gate_proof_allowance(
    DirectBaseWireRequirements &wire,
    const GateMleProverResourceBounds &gate_capacity) {
    const std::uint64_t kProofAllowance =
        gate_capacity.proof_bytes_upper_bound;
    wire.proof_bytes = checked_size(
        checked_add_u64(wire.proof_bytes, kProofAllowance,
                        "structured Base proof bytes"),
        "structured Base proof bytes");
    wire.proof_response_bytes = checked_size(
        checked_add_u64(wire.proof_response_bytes, kProofAllowance,
                        "structured Base response bytes"),
        "structured Base response bytes");
    wire.message_bytes = checked_size(
        checked_add_u64(wire.message_bytes, kProofAllowance,
                        "structured Base message bytes"),
        "structured Base message bytes");
    wire.total_field_elements = checked_size(
        checked_add_u64(wire.total_field_elements,
                        kProofAllowance / kSerializedFpBytes,
                        "structured Base field budget"),
        "structured Base field budget");
    wire.proof_resident_bytes = checked_add_u64(
        wire.proof_resident_bytes, kProofAllowance,
        "structured Base proof resident bytes");
    wire.proof_encoding_bytes = checked_add_u64(
        wire.proof_encoding_bytes, kProofAllowance,
        "structured Base proof encoding bytes");
    wire.proof_framing_bytes = checked_add_u64(
        wire.proof_framing_bytes, kProofAllowance,
        "structured Base proof framing bytes");
}

struct DiagnosticPreflight {
    explicit DiagnosticPreflight(
        CertifiedHonestPayloadSchedule certified)
        : certified_schedule(std::move(certified)) {}

    const HonestPayloadNoiseSchedule &schedule() const {
        return certified_schedule.schedule();
    }

    ReplayResourceBounds replay_bounds;
    CertifiedHonestPayloadSchedule certified_schedule;
    PublicSetup public_setup;
    PayloadCheckpointReplayProblem replay_problem;
    PayloadCheckpointReplayBudgets replay_budgets;
    PayloadCheckpointReplayPlan replay_plan;
    FileTraceStoreOptions multiplication_scratch_limits;
    std::uint64_t multiplication_sort_buffer_payload_bytes = 0;
    DirectBaseWireRequirements wire;
    BaseWireDecodeLimits wire_limits;
    protocol::BaseServerCapacityCaps capacity_caps;
    protocol::BaseServerCapacityComponents capacity_components;
    protocol::BaseServerCapacityAdmission capacity_admission;
    std::uint64_t server_preprocessing_bytes_upper = 0;
    std::uint64_t client_preprocessing_bytes_upper = 0;
    std::uint64_t client_peak_resident_bytes_upper = 0;
    std::uint64_t all_preprocessing_bytes_upper = 0;
    std::uint64_t setup_start_available_disk_bytes = 0;
    std::uint64_t server_start_available_disk_bytes = 0;
};

DiagnosticPreflight finish_diagnostic_preflight(
    const Options &options, const RunProfile &profile,
    const LayeredCircuit &circuit,
    CertifiedHonestPayloadSchedule certified_schedule,
    std::optional<PublicSetup> restored_public_setup = std::nullopt,
    std::optional<GateMleProverResourceBounds> planned_gate_capacity =
        std::nullopt) {
    if (profile.payload.gates.size() > kBenchmarkPayloadOperationCount) {
        throw std::invalid_argument(
            "diagnostic payload exceeds the 2^20-operation benchmark cap");
    }

    DiagnosticPreflight result(std::move(certified_schedule));
    result.replay_bounds = diagnostic_replay_resource_bounds(
        circuit.shape.slot_count,
        profile.seal_parameters.fresh_rns_limbs);
    if (!result.schedule().payload_model_accepts()) {
        std::ostringstream reason;
        reason << "Base noise schedule rejected before GateMLE preprocessing";
        for (const auto &layer : result.schedule().layers_in_evaluation_order) {
            if (layer.evaluated_phase_fits && layer.output_phase_fits) continue;
            const bool evaluated = !layer.evaluated_phase_fits;
            const auto limbs = evaluated ? layer.input_rns_limb_count
                                         : layer.output_rns_limb_count;
            const auto &phase = evaluated ? layer.evaluated_phase_bound
                                         : layer.output_phase_bound;
            const auto twice_phase = NaturalMagnitude::multiply(phase, 2U);
            const auto modulus = NaturalMagnitude::product(
                std::span(result.schedule().data_moduli_low_to_high).first(limbs));
            reason << ": layer " << layer.layer << " requires twice the "
                   << (evaluated ? "evaluated" : "output")
                   << " phase bound (" << twice_phase.bit_count()
                   << " bits) below its active modulus ("
                   << modulus.bit_count() << " bits, " << limbs
                   << " limbs). Review the fixed profile's noise calibration "
                      "and modulus chain before starting setup.";
            break;
        }
        throw std::invalid_argument(reason.str());
    }
    if (restored_public_setup) {
        // Both internal producers validate this exact setup against the
        // certified schedule before handing it to preflight. Repeating that
        // circuit-sized setup check here would only rescan the same payload.
        result.public_setup = std::move(*restored_public_setup);
    } else if (planned_gate_capacity) {
        result.public_setup = bind_certified_uniform_honest_base_proof_schedule(
            make_direct_setup(profile.payload, circuit), profile.payload,
            circuit, result.certified_schedule);
    } else if (options.diagnostic.assess_proof_noise) {
        HonestNoiseEnvelopeParameters proof_noise_parameters =
            derive_honest_base_proof_noise_parameters(
                circuit, result.schedule(),
                profile.base_proof_noise_calibration);
        result.public_setup = bind_honest_base_proof_noise_assessment(
            make_direct_setup(profile.payload, circuit), profile.payload,
            circuit, result.schedule(), std::move(proof_noise_parameters));
    } else {
        result.public_setup = bind_honest_payload_noise_schedule(
            make_direct_setup(profile.payload, circuit), profile.payload,
            circuit, result.schedule());
    }
    const CertifiedCanonicalTraceLayout trace_layout =
        derive_certified_canonical_trace_layout(circuit);
    result.replay_problem = make_replay_problem(
        trace_layout, result.schedule().evaluation_plan,
        result.replay_bounds);
    result.wire = direct_base_wire_requirements(
        result.certified_schedule, trace_layout,
        result.replay_bounds.serialized_ciphertext_bytes_by_rns_limb,
        result.replay_bounds.resident_ciphertext_bytes_by_rns_limb);
    const std::optional<GateMleProverResourceBounds> gate_capacity =
        result.public_setup.outsourced_gate_mle
            ? std::optional(gate_mle_prover_resource_bounds(
                  *result.public_setup.outsourced_gate_mle))
            : planned_gate_capacity;
    if (gate_capacity) {
        add_structured_gate_proof_allowance(result.wire, *gate_capacity);
    }
    // Setup plans resources from geometry before any commitments exist.
    // Its authenticated decoder limits are filled after preprocessing.
    if (!planned_gate_capacity) {
        result.wire_limits = diagnostic_wire_limits(
            result.wire, circuit, result.public_setup.outsourced_gate_mle);
    }
    const std::size_t slots = circuit.shape.slot_count;
    result.server_preprocessing_bytes_upper = diagnostic_scaled_bytes(
        slots, std::uint64_t{2} << 30U, std::uint64_t{1} << 28U,
        "diagnostic server preprocessing upper");
    result.client_preprocessing_bytes_upper =
        base_client_preprocessing_bytes_upper(slots);
    result.client_peak_resident_bytes_upper =
        base_client_peak_resident_bytes_upper(
            slots, profile.payload.input_count,
            result.client_preprocessing_bytes_upper, result.wire);
    if (options.diagnostic.client_private_persistent_disk_bytes != 0 &&
        options.diagnostic.client_private_persistent_disk_bytes !=
            result.client_preprocessing_bytes_upper) {
        throw std::logic_error(
            "Base planner and setup admission disagree on the "
            "client-private persistence reserve");
    }
    result.all_preprocessing_bytes_upper = checked_add_u64(
        checked_add_u64(result.server_preprocessing_bytes_upper,
                        result.client_preprocessing_bytes_upper,
                        "diagnostic preprocessing upper"),
        std::uint64_t{1} << 20U,
        "diagnostic preprocessing upper");

    const std::uint64_t server_resident_cap =
        reserve_concurrent_client_ram(
            options.host_budget,
            result.client_peak_resident_bytes_upper);
    result.capacity_caps = protocol::BaseServerCapacityCaps{
        .max_live_local_disk_bytes =
            options.diagnostic.max_live_disk_bytes,
        .max_resident_ram_bytes = server_resident_cap,
    };

    const std::uint64_t scaled_context_ram = diagnostic_scaled_bytes(
        slots, std::uint64_t{6} << 30U, std::uint64_t{1} << 29U,
        "diagnostic resident preprocessing upper");
    const std::uint64_t operational_ram = checked_add_u64(
        std::uint64_t{2} << 30U,
        diagnostic_scaled_bytes(
            slots, std::uint64_t{2} << 30U, 0,
            "diagnostic operational RAM scale"),
        "diagnostic operational RAM upper");
    const std::uint64_t prepared_ram = diagnostic_scaled_bytes(
        slots, std::uint64_t{1} << 30U, std::uint64_t{1} << 26U,
        "diagnostic prepared plaintext RAM upper");
    const std::uint64_t workspace_ram = diagnostic_scaled_bytes(
        slots, std::uint64_t{1} << 30U, std::uint64_t{1} << 27U,
        "diagnostic workspace RAM upper");
    const std::uint64_t proof_margin = diagnostic_scaled_bytes(
        slots, std::uint64_t{1} << 28U, std::uint64_t{1} << 25U,
        "diagnostic proof ownership margin");

    protocol::BaseServerCapacityComponents &components =
        result.capacity_components;
    components.operational_reserve = {
        std::uint64_t{1} << 30U, operational_ram};
    components.preprocessed_keys = {
        result.server_preprocessing_bytes_upper, scaled_context_ram};
    components.prepared_plaintext_cache = {0, prepared_ram};
    const auto affine_preparation_bytes = affine_gate_preparation_workspace_bytes(circuit);
    if (gate_capacity) {
        components.gate_mle_preprocessing = {
            gate_capacity->retained_prover_key_disk_bytes,
            gate_capacity->retained_prover_key_bytes};
        components.gate_mle_opening_workspace = {
            gate_capacity->opening_workspace_disk_bytes,
            checked_add_u64(gate_capacity->opening_workspace_bytes,
                            affine_preparation_bytes,
                            "Base gate opening and program construction")};
    }
    components.compact_replay_trace = {
        0, diagnostic_compact_metadata_upper(result.replay_problem)};
    components.encrypted_input_request = {
        0, result.wire.input_resident_bytes};
    components.encrypted_output_response = {
        0, result.wire.output_resident_bytes};
    const std::uint64_t storage_aware_workspace = checked_add_u64(
        workspace_ram, kPayloadStorageTransferResidentBytes,
        "payload workspace and storage-transfer buffers");
    components.payload_replay_workspace = {0, storage_aware_workspace};
    components.affine_reduction_workspace = {
        0, checked_add_u64(storage_aware_workspace,
                           affine_preparation_bytes,
                           "Base affine public preparation workspace")};
    components.multiplication_builder_workspace = {
        0, storage_aware_workspace};
    components.multiplication_reduction_workspace = {
        0, storage_aware_workspace};
    components.accumulated_proof = {
        0, checked_add_u64(result.wire.proof_resident_bytes, proof_margin,
                           "diagnostic accumulated proof upper")};
    components.proof_encoding = {
        0, checked_add_u64(result.wire.proof_encoding_bytes, proof_margin,
                           "diagnostic proof encoding upper")};
    components.transport_framing = {
        0, checked_add_u64(result.wire.proof_framing_bytes, proof_margin,
                           "diagnostic transport framing upper")};
    bind_direct_multiplication_capacity_to_circuit(
        trace_layout, result.replay_problem, components, false);

    const auto multiplication_disk =
        diagnostic_multiplication_disk_bounds(trace_layout,
                                              result.replay_problem);
    result.multiplication_scratch_limits = FileTraceStoreOptions{
        .max_total_bytes = multiplication_disk.build_peak_bytes,
        .min_free_bytes = options.diagnostic.min_free_disk_bytes,
    };
    components.multiplication_build_scratch = {
        multiplication_disk.build_peak_bytes, 0};
    components.multiplication_artifact = {
        multiplication_disk.completed_artifact_bytes, 0};
    const protocol::ServerResourcePair replay_reserve =
        base_server_detail::required_payload_replay_reserve(components);
    result.replay_budgets = PayloadCheckpointReplayBudgets{
        .max_live_scratch_bytes =
            options.diagnostic.max_live_disk_bytes,
        .max_resident_ciphertext_bytes =
            result.capacity_caps.max_resident_ram_bytes,
        .max_ciphertexts_per_chunk =
            options.diagnostic.max_replay_chunk_ciphertexts,
        // Keep every measured run inside the intended 2.5x cumulative
        // payload-work envelope. Adaptive profiles spend whatever disk
        // headroom setup admitted to minimize replay work.
        .max_recomputation_factor =
            kDiagnosticMaximumRecomputationFactor,
        .reserved_live_scratch_bytes = replay_reserve.local_disk_bytes,
        .reserved_resident_bytes = replay_reserve.resident_ram_bytes,
        .selection_objective =
            options.diagnostic.checkpoint_selection_objective,
    };
    result.replay_plan = plan_payload_checkpoint_replay(
        result.replay_problem, result.replay_budgets);
    require(result.replay_plan.selected.feasible(),
            "diagnostic checkpoint replay plan is infeasible");
    if (options.diagnostic.require_zero_payload_replay) {
        require(
            result.replay_plan.selected.replay_work_units == 0,
            "target qualification failed: actual disk/RAM capacity and "
            "reserves selected nonzero payload replay; do not start the "
            "expensive run");
    }
    validate_payload_checkpoint_relation_chunk_capacity(
        trace_layout, result.replay_plan.selected.chunk_ciphertexts);
    require(result.replay_plan.selected.checkpoint_layers.size() <
                circuit.layers.size(),
            "diagnostic replay unexpectedly retained the full trace");

    protocol::BaseServerCapacityComponents admitted_components = components;
    admitted_components.payload_replay_phase_floor = {
        result.replay_plan.selected.peak_live_scratch_bytes,
        result.replay_plan.selected.peak_resident_bytes};
    admitted_components.compact_replay_trace.local_disk_bytes =
        base_server_detail::compact_replay_post_replay_disk(
            result.replay_problem, result.replay_plan);
    admitted_components.compact_replay_trace.resident_ram_bytes = std::max(
        admitted_components.compact_replay_trace.resident_ram_bytes,
        base_server_detail::compact_replay_record_metadata_ram(
            result.replay_problem, result.replay_plan));

    // Spend otherwise idle host RAM on the external bit-reversal sort used
    // to build multiplication sources.  The capacity cap already excludes
    // the OS reserve and the waiting client.  The sorter treats this as an
    // upper bound and allocates only enough memory for the current layer.
    const protocol::BaseServerCapacityAdmission fixed_admission =
        protocol::admit_base_server_capacity(
            result.capacity_caps, admitted_components);
    const auto &fixed_builder = fixed_admission.phase(
        protocol::BaseServerCapacityPhase::MultiplicationScratchBuild);
    require(result.capacity_caps.max_resident_ram_bytes >=
                fixed_builder.resident_ram_bytes,
            "Base fixed multiplication-builder RAM exceeds its cap");
    // Half the remaining RAM holds serialized payload; the other half covers
    // owned buffer capacity, sort records and merge bookkeeping.
    result.multiplication_sort_buffer_payload_bytes =
        (result.capacity_caps.max_resident_ram_bytes -
         fixed_builder.resident_ram_bytes) / 2U;
    require(result.multiplication_sort_buffer_payload_bytes >=
                gkr::detail::kDenseMultiplicationSortMaxBufferedPayloadBytes,
            "host RAM leaves less than 4 GiB for multiplication-source "
            "ordering");
    components.multiplication_builder_workspace.resident_ram_bytes =
        checked_add_u64(
            components.multiplication_builder_workspace.resident_ram_bytes,
            checked_multiply_u64(
                result.multiplication_sort_buffer_payload_bytes, 2U,
                "Base multiplication sort-buffer allocation"),
            "Base multiplication sort-buffer workspace");
    admitted_components.multiplication_builder_workspace =
        components.multiplication_builder_workspace;
    result.capacity_admission =
        protocol::admit_base_server_capacity(
            result.capacity_caps, admitted_components);

    result.setup_start_available_disk_bytes =
        protocol::required_base_setup_available_disk(
            result.capacity_admission,
            result.client_preprocessing_bytes_upper,
            result.all_preprocessing_bytes_upper,
            options.diagnostic.min_free_disk_bytes);
    result.server_start_available_disk_bytes =
        protocol::required_base_server_available_disk(
            result.capacity_admission,
            checked_add_u64(
                result.server_preprocessing_bytes_upper,
                gate_capacity
                    ? gate_capacity->retained_prover_key_disk_bytes
                    : 0,
                "persisted Base server preprocessing"),
            options.diagnostic.min_free_disk_bytes);

    return result;
}

enum class DiagnosticHostAdmissionPoint {
    SetupStart,
    ServerStart,
};

const char *diagnostic_capacity_phase_name(
    protocol::BaseServerCapacityPhase phase) {
    switch (phase) {
    case protocol::BaseServerCapacityPhase::PreprocessedReady:
        return "preprocessed-ready";
    case protocol::BaseServerCapacityPhase::PayloadCheckpointReplay:
        return "payload/checkpoint-replay";
    case protocol::BaseServerCapacityPhase::AffineReduction:
        return "Base affine reduction";
    case protocol::BaseServerCapacityPhase::MultiplicationScratchBuild:
        return "Base multiplication-scratch build";
    case protocol::BaseServerCapacityPhase::MultiplicationReduction:
        return "Base multiplication reduction";
    case protocol::BaseServerCapacityPhase::GateMleOpening:
        return "Base GateMLE opening";
    case protocol::BaseServerCapacityPhase::ProofPublication:
        return "Base proof publication";
    }
    throw std::logic_error("unknown Base capacity phase");
}

std::uint64_t diagnostic_required_available_disk(
    const Options &options, const DiagnosticPreflight &preflight,
    DiagnosticHostAdmissionPoint point,
    std::uint64_t already_present_gate_bytes = 0) {
    require(already_present_gate_bytes <=
                preflight.capacity_components.gate_mle_preprocessing.local_disk_bytes,
            "persisted GateMLE allowance exceeds the admitted cache");
    if (point == DiagnosticHostAdmissionPoint::ServerStart) {
        require(already_present_gate_bytes == 0,
                "server-start admission already accounts for persisted GateMLE state");
        return preflight.server_start_available_disk_bytes;
    }
    require(already_present_gate_bytes <= preflight.setup_start_available_disk_bytes,
            "persisted GateMLE allowance exceeds setup disk demand");
    // Subtract the GateMLE cache already on disk from the lifecycle demand.
    // FHE preprocessing and the free-space reserve must still fit.
    return std::max(preflight.setup_start_available_disk_bytes - already_present_gate_bytes,
        checked_add_u64(preflight.all_preprocessing_bytes_upper,
                        options.diagnostic.min_free_disk_bytes,
                        "remaining Base preprocessing disk requirement"));
}

std::uint64_t require_diagnostic_host(
    const Options &options, const DiagnosticPreflight &preflight,
    DiagnosticHostAdmissionPoint point,
    std::uint64_t already_present_gate_bytes = 0) {
    const SystemInfo host = system_info();
    std::uint64_t required_host_ram_bytes =
        preflight.capacity_caps.max_resident_ram_bytes;
    const std::uint64_t expected_server_cap =
        reserve_concurrent_client_ram(
            options.host_budget,
            preflight.client_peak_resident_bytes_upper);
    require(expected_server_cap ==
                preflight.capacity_caps.max_resident_ram_bytes,
            "Base client/server RAM accounting drifted");
    required_host_ram_bytes = checked_add_u64(
        checked_add_u64(expected_server_cap,
                        preflight.client_peak_resident_bytes_upper,
                        "Base concurrent resident envelope"),
        kBenchmarkHostRamSafetyReserveBytes,
        "Base physical RAM requirement");
    if (host.ram_bytes == 0 || host.ram_bytes < required_host_ram_bytes) {
        throw std::runtime_error(
            "diagnostic host has " + std::to_string(host.ram_bytes) +
            " physical RAM bytes; the selected profile requires at least " +
            std::to_string(required_host_ram_bytes));
    }
    std::error_code error;
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(options.work_directory, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        throw std::invalid_argument(
            "--work-dir must be an existing, non-symlink directory");
    }
    const std::filesystem::space_info space =
        std::filesystem::space(options.work_directory, error);
    if (error ||
        space.available > std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error(
            "cannot inspect available disk bytes at diagnostic work "
            "directory " + options.work_directory.string());
    }
    const std::uint64_t available =
        static_cast<std::uint64_t>(space.available);
    const std::uint64_t required = diagnostic_required_available_disk(
        options, preflight, point, already_present_gate_bytes);
    if (available < required) {
        const auto &peak =
            preflight.capacity_admission.peak_live_local_disk_phase();
        std::ostringstream message;
        message << "insufficient free disk for Base "
                << (point == DiagnosticHostAdmissionPoint::SetupStart
                        ? "setup"
                        : "server start")
                << " at " << options.work_directory << ":\n"
                << "  available: " << available << " bytes\n"
                << "  required now: " << required << " bytes\n"
                << "  shortfall: " << required - available << " bytes\n"
                << "  predicted peak live server disk: "
                << preflight.capacity_admission.max_live_local_disk_bytes
                << " bytes (" << diagnostic_capacity_phase_name(peak.phase)
                << " phase)\n";
        if (point == DiagnosticHostAdmissionPoint::SetupStart) {
            message << "  coexisting client-preprocessing allowance: "
                    << preflight.client_preprocessing_bytes_upper
                    << " bytes\n"
                    << "  GateMLE preprocessing already present: "
                    << already_present_gate_bytes << " bytes\n";
        } else {
            message << "  server preprocessing already present: "
                    << preflight.server_preprocessing_bytes_upper
                    << " bytes (not counted twice)\n";
        }
        message << "  required post-peak free-space reserve: "
                << options.diagnostic.min_free_disk_bytes << " bytes\n"
                << "  configured live-server cap: "
                << options.diagnostic.max_live_disk_bytes
                << " bytes (admission ceiling, not predicted allocation)";
        throw std::runtime_error(message.str());
    }
    return available;
}

DiagnosticPreflight preflight_diagnostic(
    const Options &options, const RunProfile &profile,
    const LayeredCircuit &circuit, std::size_t proof_ingress_rns_limbs,
    std::size_t preprocessing_threads,
    const std::function<void(std::string_view, std::string_view)> &stage) {
    stage("schedule_preflight", "certifying the fixed Base noise schedule");
    CertifiedHonestPayloadSchedule certified_schedule =
        derive_certified_uniform_honest_base_proof_schedule(
            circuit, profile.seal_parameters.exact_data_primes,
            profile.calibration, proof_ingress_rns_limbs);
    const gates::GateTableBuildOptions gate_options{
        .wide_scratch_parent = options.work_directory / "gate-mle-scratch",
        .wide_max_disk_bytes = options.diagnostic.max_live_disk_bytes,
        .wide_resources = {
            .min_free_bytes = options.diagnostic.min_free_disk_bytes},
        .preprocessing_threads = preprocessing_threads,
        .prover_key_directory = options.work_directory / "server" / "preprocessing" / "gate-mle"};
    stage("resource_preflight",
          "checking every Base server phase before GateMLE preprocessing");
    const auto gate_plan = plan_gate_mle_preprocessing(
        circuit, gates::GateTableSet::Wide, gate_options);
    require(gate_plan.basefold_soundness_bits >= kTargetSecurityBits,
            "GateMLE geometry does not meet the required soundness before preprocessing");
    DiagnosticPreflight result = finish_diagnostic_preflight(
        options, profile, circuit, std::move(certified_schedule),
        std::nullopt, gate_plan.resources);
    const std::uint64_t available = require_diagnostic_host(
        options, result, DiagnosticHostAdmissionPoint::SetupStart);
    require(available >= checked_add_u64(
                gate_plan.commitment_peak_disk_bytes,
                options.diagnostic.min_free_disk_bytes,
                "GateMLE setup disk requirement"),
            "insufficient free disk for GateMLE commitment construction");
    if (options.diagnostic.workload_kind == WorkloadKind::MulHeavyPyramid &&
        options.diagnostic.slots == 16384 &&
        options.diagnostic.operation_count == 1048576 &&
        options.diagnostic.seed == 1) {
        stage("target_ciphertext_noise_preflight",
              "checking exact pyramid dependency cones before GateMLE preprocessing");
        const auto inputs = make_workload_inputs(
            diagnostic_workload_spec(options.diagnostic));
        require_target_pyramid_noise_preflight(
            profile.payload, circuit, inputs, profile.seal_parameters,
            result.schedule().evaluation_plan,
            options.diagnostic.max_resident_ram_bytes, std::cout);
    }
    stage("gate_mle_preprocessing",
          "capacity checks passed; constructing structured GateMLE commitments");
    OutsourcedGateMleSetupArtifacts gate_mle =
        preprocess_outsourced_gate_mle_setup(
            profile.payload, circuit, gates::GateTableSet::Wide, gate_options);
    require(gate_mle_prover_resource_bounds(
                *gate_mle.public_setup.outsourced_gate_mle) ==
                gate_plan.resources,
            "GateMLE preprocessing resource bounds differ from preflight");
    result.public_setup = bind_certified_uniform_honest_base_proof_schedule(
        std::move(gate_mle.public_setup), profile.payload, circuit,
        result.certified_schedule);
    result.wire_limits = diagnostic_wire_limits(
        result.wire, circuit, result.public_setup.outsourced_gate_mle);
    return result;
}

std::string json_string(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 2U);
    result.push_back('"');
    for (const char character : value) {
        switch (character) {
        case '"':
            result += "\\\"";
            break;
        case '\\':
            result += "\\\\";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            result.push_back(character);
            break;
        }
    }
    result.push_back('"');
    return result;
}

/// Persistent, line-buffered diagnostics for the server process. Each
/// boundary is flushed before protocol work continues, so the last BEGIN or
/// progress record identifies the active phase after an interruption.
class ProgressRecorder {
  public:
    explicit ProgressRecorder(std::filesystem::path path)
        : path_(std::move(path)),
          run_start_(std::chrono::steady_clock::now()),
          uncaught_on_entry_(std::uncaught_exceptions()) {
        std::error_code error;
        if (std::filesystem::exists(path_, error) || error) {
            throw std::runtime_error(
                "Base server progress file already exists or cannot be "
                "checked");
        }
        output_.open(path_, std::ios::out | std::ios::trunc);
        if (!output_) {
            throw std::runtime_error(
                "failed to create persistent Base progress file");
        }
        std::error_code permission_error;
        std::filesystem::permissions(
            path_,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, permission_error);
        if (permission_error) {
            output_.close();
            std::error_code ignored;
            std::filesystem::remove(path_, ignored);
            throw std::runtime_error(
                "failed to make Base progress file owner-only");
        }
        std::cerr << "telemetry.progress_file=" << path_.string()
                  << std::endl;
        write_status("started");
    }

    ProgressRecorder(const ProgressRecorder &) = delete;
    ProgressRecorder &operator=(const ProgressRecorder &) = delete;

    ~ProgressRecorder() {
        if (std::uncaught_exceptions() > uncaught_on_entry_) {
            write_status("failed");
        }
    }

    RuntimeProgressCallback callback() {
        return [this](const RuntimeProgressEvent &event) noexcept {
            observe(event);
        };
    }

    void begin_phase(std::string_view name) noexcept {
        try {
            NamedActive active;
            active.name = std::string(name);
            active.wall_start = std::chrono::steady_clock::now();
            active.cpu_start = std::clock();
            named_active_.push_back(active);
            write_boundary("begin", active.name, std::nullopt);
        } catch (...) {
            disable_once();
        }
    }

    void end_phase(std::string_view name) noexcept {
        try {
            for (std::size_t index = named_active_.size(); index-- > 0;) {
                if (named_active_[index].name != name) {
                    continue;
                }
                const Timing timing = elapsed(
                    named_active_[index].wall_start,
                    named_active_[index].cpu_start);
                completed_.push_back(CompletedSpan{
                    named_active_[index].name, timing, std::nullopt});
                named_active_.erase(
                    named_active_.begin() +
                    static_cast<std::ptrdiff_t>(index));
                write_boundary("end", name, timing);
                return;
            }
            write_boundary("unmatched-end", name, std::nullopt);
        } catch (...) {
            disable_once();
        }
    }

    void mark_server_complete() noexcept {
        write_status("server-complete");
    }

    void emit(const Record &record) const {
        record.text("telemetry.schema", "laminate-base-progress-v1");
        record.text("telemetry.progress_file", path_.string());
        record.text("telemetry.logging_status",
                    disabled_ ? "failed" : "complete");
        record.real("timing.progress_observed_total.wall_ms",
                    run_elapsed_ms());
        record.text(
            "timing.progress_observed_total.scope",
            "post-preflight-progress-recorder-lifetime-through-report-"
            "emission;includes-setup-role-work-codecs-proof-size-accounting-"
            "and-runtime-reconciliation");
        record.integer("telemetry.completed_spans", completed_.size());
        for (std::size_t index = 0; index < completed_.size(); ++index) {
            const std::string prefix =
                "telemetry.span." + std::to_string(index);
            record.text(prefix + ".name", completed_[index].name);
            record.real(prefix + ".wall_ms",
                        completed_[index].timing.wall_ms);
            record.real(prefix + ".cpu_ms",
                        completed_[index].timing.cpu_ms);
            if (completed_[index].event) {
                const RuntimeProgressEvent &event = *completed_[index].event;
                record.text(prefix + ".stage",
                            protocol_progress_stage_name(event.stage));
                record.text(prefix + ".layer_kind",
                            protocol_progress_layer_name(event.layer_kind));
                if (event.coordinate_domain !=
                    RuntimeProgressCoordinateDomain::Unspecified) {
                    record.text(
                        prefix + ".coordinate_domain",
                        protocol_progress_coordinate_domain_name(
                            event.coordinate_domain));
                }
                emit_index(record, prefix, "reduction_layer",
                           event.reduction_layer);
                emit_index(record, prefix, "source_layer",
                           event.source_layer);
                emit_index(record, prefix, "output_layer",
                           event.output_layer);
                emit_index(record, prefix, "checkpoint_layer",
                           event.checkpoint_layer);
                emit_index(record, prefix, "round", event.round);
                if (event.round_count != 0) {
                    record.integer(prefix + ".round_count",
                                   event.round_count);
                }
                if (event.side != RuntimeProgressSide::Unspecified) {
                    record.text(prefix + ".side",
                                protocol_progress_side_name(event.side));
                }
                if (event.work_units != 0) {
                    record.integer(prefix + ".work_units",
                                   event.work_units);
                }
            }
        }
    }

  private:
    struct RuntimeActive {
        RuntimeProgressEvent event;
        std::chrono::steady_clock::time_point wall_start;
        std::clock_t cpu_start = 0;
    };

    struct NamedActive {
        std::string name;
        std::chrono::steady_clock::time_point wall_start;
        std::clock_t cpu_start = 0;
    };

    struct CompletedSpan {
        std::string name;
        Timing timing;
        std::optional<RuntimeProgressEvent> event;
    };

    static void emit_index(const Record &record, const std::string &prefix,
                           std::string_view name, std::size_t value) {
        if (value != kRuntimeProgressNoIndex) {
            record.integer(prefix + '.' + std::string(name), value);
        }
    }

    static bool same_span(const RuntimeProgressEvent &left,
                          const RuntimeProgressEvent &right) {
        return left.stage == right.stage &&
               left.layer_kind == right.layer_kind &&
               left.side == right.side &&
               left.coordinate_domain == right.coordinate_domain &&
               left.reduction_layer == right.reduction_layer &&
               left.source_layer == right.source_layer &&
               left.output_layer == right.output_layer &&
               left.checkpoint_layer == right.checkpoint_layer &&
               left.round == right.round &&
               left.column_index == right.column_index;
    }

    static Timing elapsed(
        std::chrono::steady_clock::time_point wall_start,
        std::clock_t cpu_start) {
        const auto wall_end = std::chrono::steady_clock::now();
        const std::clock_t cpu_end = std::clock();
        const double cpu_ms =
            cpu_start == static_cast<std::clock_t>(-1) ||
                    cpu_end == static_cast<std::clock_t>(-1)
                ? 0.0
                : 1000.0 * static_cast<double>(cpu_end - cpu_start) /
                      static_cast<double>(CLOCKS_PER_SEC);
        return Timing{
            std::chrono::duration<double, std::milli>(wall_end - wall_start)
                .count(),
            cpu_ms};
    }

    double run_elapsed_ms() const {
        return std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - run_start_)
            .count();
    }

    void observe(const RuntimeProgressEvent &event) noexcept {
        try {
            const std::string name = protocol_progress_span_name(event);
            if (event.boundary == RuntimeProgressBoundary::Begin) {
                runtime_active_.push_back(RuntimeActive{
                    event, std::chrono::steady_clock::now(), std::clock()});
                write_boundary("begin", name, std::nullopt, &event);
                return;
            }
            if (event.boundary == RuntimeProgressBoundary::Update) {
                write_boundary("progress", name, std::nullopt, &event);
                return;
            }
            for (std::size_t index = runtime_active_.size(); index-- > 0;) {
                if (!same_span(runtime_active_[index].event, event)) {
                    continue;
                }
                const Timing timing = elapsed(
                    runtime_active_[index].wall_start,
                    runtime_active_[index].cpu_start);
                completed_.push_back(CompletedSpan{name, timing, event});
                runtime_active_.erase(
                    runtime_active_.begin() +
                    static_cast<std::ptrdiff_t>(index));
                write_boundary("end", name, timing, &event);
                return;
            }
            write_boundary("unmatched-end", name, std::nullopt, &event);
        } catch (...) {
            disable_once();
        }
    }

    void write_boundary(
        std::string_view boundary, std::string_view name,
        std::optional<Timing> timing,
        const RuntimeProgressEvent *event = nullptr) {
        if (disabled_) {
            return;
        }
        output_ << '{'
                << "\"schema\":\"laminate-base-progress-v1\","
                << "\"seq\":" << sequence_++ << ','
                << "\"event\":" << json_string(boundary) << ','
                << "\"stage\":" << json_string(name) << ','
                << "\"run_elapsed_ms\":" << std::fixed
                << std::setprecision(3) << run_elapsed_ms();
        if (timing) {
            output_ << ",\"wall_ms\":" << timing->wall_ms
                    << ",\"cpu_ms\":" << timing->cpu_ms;
        }
        if (event != nullptr) {
            output_ << ",\"layer_kind\":"
                    << json_string(
                           protocol_progress_layer_name(event->layer_kind));
            write_index("reduction_layer", event->reduction_layer);
            write_index("source_layer", event->source_layer);
            write_index("output_layer", event->output_layer);
            write_index("checkpoint_layer", event->checkpoint_layer);
            write_index("round", event->round);
            if (event->round_count != 0) {
                output_ << ",\"rounds\":" << event->round_count;
            }
            if (event->side != RuntimeProgressSide::Unspecified) {
                output_ << ",\"side\":"
                        << json_string(
                               protocol_progress_side_name(event->side));
            }
            if (event->coordinate_domain !=
                RuntimeProgressCoordinateDomain::Unspecified) {
                output_ << ",\"coordinate_domain\":"
                        << json_string(
                               protocol_progress_coordinate_domain_name(
                                   event->coordinate_domain));
            }
            if (event->subpass != RuntimeProgressSubpass::Unspecified) {
                output_ << ",\"subpass\":"
                        << json_string(protocol_progress_subpass_name(
                               event->subpass));
            }
            if (event->progress_work_unit !=
                RuntimeProgressWorkUnit::Unspecified) {
                output_ << ",\"progress_work_unit\":"
                        << json_string(protocol_progress_work_unit_name(
                               event->progress_work_unit));
            }
            if (event->work_units != 0) {
                output_ << ",\"work_units\":" << event->work_units;
            }
            if (event->total_steps != 0) {
                output_ << ",\"completed_steps\":"
                        << event->completed_steps
                        << ",\"total_steps\":" << event->total_steps;
            }
            if (event->total_work_units != 0) {
                output_ << ",\"completed_work_units\":"
                        << event->completed_work_units
                        << ",\"total_work_units\":"
                        << event->total_work_units;
            }
            if (event->phase_total_steps != 0) {
                output_ << ",\"phase_completed_steps\":"
                        << event->phase_completed_steps
                        << ",\"phase_total_steps\":"
                        << event->phase_total_steps;
            }
            if (event->total_read_bytes != 0) {
                output_ << ",\"completed_read_bytes\":"
                        << event->completed_read_bytes
                        << ",\"total_read_bytes\":"
                        << event->total_read_bytes;
            }
            if (event->total_write_bytes != 0) {
                output_ << ",\"completed_write_bytes\":"
                        << event->completed_write_bytes
                        << ",\"total_write_bytes\":"
                        << event->total_write_bytes;
            }
            if (event->phase_total_read_bytes != 0) {
                output_ << ",\"phase_completed_read_bytes\":"
                        << event->phase_completed_read_bytes
                        << ",\"phase_total_read_bytes\":"
                        << event->phase_total_read_bytes;
            }
            if (event->phase_total_write_bytes != 0) {
                output_ << ",\"phase_completed_write_bytes\":"
                        << event->phase_completed_write_bytes
                        << ",\"phase_total_write_bytes\":"
                        << event->phase_total_write_bytes;
            }
            if (event->total_butterflies != 0) {
                output_ << ",\"completed_butterflies\":"
                        << event->completed_butterflies
                        << ",\"total_butterflies\":"
                        << event->total_butterflies;
            }
            if (event->phase_total_butterflies != 0) {
                output_ << ",\"phase_completed_butterflies\":"
                        << event->phase_completed_butterflies
                        << ",\"phase_total_butterflies\":"
                        << event->phase_total_butterflies;
            }
            if (event->radix_elements != 0) {
                output_ << ",\"radix_elements\":"
                        << event->radix_elements;
            }
            if (event->row_count != 0) {
                output_ << ",\"row_count\":" << event->row_count;
            }
            if (event->row_size != 0) {
                output_ << ",\"row_size\":" << event->row_size;
            }
            if (event->recent_work_units != 0 &&
                event->recent_elapsed_milliseconds != 0) {
                output_ << ",\"recent_work_units\":"
                        << event->recent_work_units
                        << ",\"recent_elapsed_ms\":"
                        << event->recent_elapsed_milliseconds
                        << ",\"recent_work_units_per_second\":"
                        << std::setprecision(3)
                        << 1000.0 *
                               static_cast<double>(event->recent_work_units) /
                               static_cast<double>(
                                   event->recent_elapsed_milliseconds)
                        << ",\"estimated_remaining_ms\":"
                        << event->estimated_remaining_milliseconds;
            }
            write_index("column_index", event->column_index);
            if (event->column_count != 0) {
                output_ << ",\"column_count\":"
                        << event->column_count;
            }
            append_protocol_progress_diagnostics_json(output_, *event);
        }
        output_ << "}\n";
        output_.flush();
        if (!output_) {
            disable_once();
            return;
        }
        std::cerr << "progress " << boundary << ' ';
        if (event != nullptr) {
            std::cerr << protocol_progress_human_description(*event)
                      << " [stage=" << name << ']';
        } else {
            std::cerr << name;
        }
        std::cerr << " elapsed_ms=" << std::fixed
                  << std::setprecision(0) << run_elapsed_ms();
        if (timing) {
            std::cerr << " wall_ms=" << std::setprecision(3)
                      << timing->wall_ms;
        }
        std::cerr << std::endl;
    }

    void write_index(std::string_view name, std::size_t value) {
        if (value != kRuntimeProgressNoIndex) {
            output_ << ",\"" << name << "\":" << value;
        }
    }

    void write_status(std::string_view status) noexcept {
        try {
            if (disabled_) {
                return;
            }
            output_ << '{'
                    << "\"schema\":\"laminate-base-progress-v1\","
                    << "\"seq\":" << sequence_++ << ','
                    << "\"event\":\"run-status\","
                    << "\"status\":" << json_string(status) << ','
                    << "\"run_elapsed_ms\":" << std::fixed
                    << std::setprecision(3) << run_elapsed_ms();
            if (status == "complete") {
                output_ << ",\"verification_result\":\"PASS\""
                        << ",\"result_file_status\":"
                           "\"pending-publication\""
                        << ",\"next_action\":"
                           "\"require-result-file-PASS-and-zero-exit\"";
            } else if (status == "server-complete") {
                output_ << ",\"response_status\":\"published\""
                        << ",\"next_action\":"
                           "\"wait-for-client-verification-PASS\"";
            }
            if (status == "failed" && !runtime_active_.empty()) {
                output_ << ",\"last_active_stage\":"
                        << json_string(protocol_progress_span_name(
                               runtime_active_.back().event));
            } else if (status == "failed" && !named_active_.empty()) {
                output_ << ",\"last_active_stage\":"
                        << json_string(named_active_.back().name);
            }
            output_ << "}\n";
            output_.flush();
            if (!output_) {
                disable_once();
            }
        } catch (...) {
            disable_once();
        }
    }

    void disable_once() noexcept {
        if (disabled_) {
            return;
        }
        disabled_ = true;
        std::cerr << "warning: Base progress logging failed; protocol "
                     "execution continues"
                  << std::endl;
    }

    std::filesystem::path path_;
    std::ofstream output_;
    std::chrono::steady_clock::time_point run_start_;
    int uncaught_on_entry_ = 0;
    std::size_t sequence_ = 0;
    bool disabled_ = false;
    std::vector<RuntimeActive> runtime_active_;
    std::vector<NamedActive> named_active_;
    std::vector<CompletedSpan> completed_;
};

void write_private_bundle(const std::filesystem::path &path,
                          std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        throw std::invalid_argument("cannot persist an empty SEAL bundle");
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output ||
        bytes.size() > static_cast<std::size_t>(
                           std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("failed to open preprocessing bundle");
    }
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.close();
    if (!output) {
        throw std::runtime_error("failed to persist preprocessing bundle");
    }
    std::error_code error;
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_read |
                  std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, error);
    if (error) {
        throw std::runtime_error(
            "failed to make preprocessing bundle owner-only");
    }
}

enum class ProcessAction : std::uint8_t {
    Setup,
    RunClient,
    RunServer,
    Status,
    VerifySavedResponse,
};

struct ProcessCommand {
    ProcessAction action = ProcessAction::Status;
    std::string variant;
    std::string profile;
    std::filesystem::path run_directory;
    std::filesystem::path recover_from;
    std::filesystem::path output_directory;
};

struct ProcessProfile {
    std::string_view name;
    WorkloadKind workload_kind = WorkloadKind::Diamond;
    std::size_t multiplicative_depth = 0;
    // Constant Diamond width or first MulHeavyPyramid multiplication width.
    std::size_t middle_width = 0;
    std::size_t operation_count = 0;
    std::size_t inputs = kBenchmarkDiamondInputCiphertexts;
    std::size_t proof_ingress_rns_limbs = 3;
};

constexpr std::string_view kProcessSetupDomain =
    "LaminateImpl/BaseProcessSetup/v11";
constexpr std::size_t kProcessMaximumSetupBytes = 64U << 20U;
constexpr std::size_t kProcessMaximumProfileBytes = 64;

bool is_process_action(std::string_view argument) {
    return argument == "setup" || argument == "run_client" ||
           argument == "run_server" || argument == "status" ||
           argument == "verify_saved_response";
}

ProcessCommand parse_process_command(int argc, char **argv) {
    if (argc != 8 && argc != 10) {
        throw std::invalid_argument(
            "process mode expects ACTION --variant base --profile "
            "quick|target-balancedLaned|target-mulHeavyPyramid --run-dir "
            "ABSOLUTE_PATH [--recover-from FAILED_RUN (setup only) | "
            "--output-dir NEW_DIRECTORY (verify_saved_response only)]");
    }
    ProcessCommand result;
    const std::string_view action(argv[1]);
    if (action == "setup") {
        result.action = ProcessAction::Setup;
    } else if (action == "run_client") {
        result.action = ProcessAction::RunClient;
    } else if (action == "run_server") {
        result.action = ProcessAction::RunServer;
    } else if (action == "status") {
        result.action = ProcessAction::Status;
    } else if (action == "verify_saved_response") {
        result.action = ProcessAction::VerifySavedResponse;
    } else {
        throw std::invalid_argument("unknown process action");
    }
    if (std::string_view(argv[2]) != "--variant" ||
        std::string_view(argv[4]) != "--profile" ||
        std::string_view(argv[6]) != "--run-dir") {
        throw std::invalid_argument(
            "process options must be exactly --variant, --profile, then "
            "--run-dir");
    }
    result.variant = argv[3];
    result.profile = argv[5];
    result.run_directory = argv[7];
    if (result.action == ProcessAction::VerifySavedResponse) {
        if (argc != 10 || std::string_view(argv[8]) != "--output-dir")
            throw std::invalid_argument(
                "verify_saved_response requires --output-dir NEW_DIRECTORY");
        result.output_directory = argv[9];
        if (!result.output_directory.is_absolute() ||
            result.output_directory == result.output_directory.root_path())
            throw std::invalid_argument(
                "--output-dir requires an absolute new directory");
    } else if (argc == 10) {
        if (result.action != ProcessAction::Setup ||
            std::string_view(argv[8]) != "--recover-from") {
            throw std::invalid_argument(
                "only setup accepts --recover-from FAILED_RUN");
        }
        result.recover_from = argv[9];
        if (!result.recover_from.is_absolute() ||
            result.recover_from == result.recover_from.root_path()) {
            throw std::invalid_argument(
                "--recover-from requires an absolute failed-run directory");
        }
    }
    if (result.variant != "base") {
        throw std::invalid_argument(
            "only the Base standalone process adapter is implemented");
    }
    const auto tier = benchmark_payload_tier(result.profile);
    if (result.action != ProcessAction::Status &&
        !benchmark_profile_is_in_campaign(result.variant, tier)) {
        throw std::invalid_argument(
            "current benchmark campaign permits Base on both target profiles; "
            "quick diagnostics remain available");
    }
    if (!result.run_directory.is_absolute() ||
        result.run_directory == result.run_directory.root_path()) {
        throw std::invalid_argument(
            "--run-dir must be an absolute path below the filesystem root");
    }
    return result;
}

ProcessProfile process_profile(std::string_view name) {
    const BenchmarkPayloadProfile selected =
        benchmark_payload_profile(name);
    return ProcessProfile{
        .name = selected.name,
        .workload_kind = selected.workload_kind,
        .multiplicative_depth = selected.depth,
        .middle_width = selected.width,
        .operation_count = selected.operation_count,
        .inputs = selected.inputs,
        .proof_ingress_rns_limbs = 3,
    };
}

Options process_options(const ProcessCommand &command,
                        const ProcessProfile &selected,
                        const HostResourceBudget &host_budget) {
    Options result;
    result.work_directory = command.run_directory;
    result.host_budget = host_budget;
    result.diagnostic.slots = kDiagnosticDefaultSlots;
    result.diagnostic.depth = selected.multiplicative_depth;
    result.diagnostic.width = selected.middle_width;
    result.diagnostic.inputs = selected.inputs;
    result.diagnostic.seed = 1;
    result.diagnostic.workload_kind = selected.workload_kind;
    const auto workload = benchmark_payload_workload_spec(
        benchmark_payload_profile(selected.name),
        PayloadShape::wide(result.diagnostic.slots));
    result.diagnostic.operation_count = workload.operation_count;
    result.diagnostic.multiplication_widths = workload.multiplication_widths;
    if (derive_host_resource_budget(
            host_budget.observed_available_disk_bytes,
            host_budget.observed_physical_ram_bytes) != host_budget) {
        throw std::invalid_argument(
            "Base options require a canonical setup-bound host budget");
    }
    result.diagnostic.max_live_disk_bytes = reserve_role_private_disk(
        host_budget,
        base_client_preprocessing_bytes_upper(result.diagnostic.slots));
    result.diagnostic.max_resident_ram_bytes =
        host_budget.max_resident_ram_bytes;
    result.diagnostic.min_free_disk_bytes =
        kBenchmarkFreeDiskReserveBytes;
    result.diagnostic.client_private_persistent_disk_bytes =
        base_client_preprocessing_bytes_upper(result.diagnostic.slots);
    result.diagnostic.max_replay_chunk_ciphertexts =
        kDiagnosticDefaultReplayChunkCiphertexts;
    result.diagnostic.checkpoint_selection_objective =
        PayloadCheckpointSelectionObjective::MinimumReplayWork;
    // Process setup uses the committed uniform policy. Exhaustive operational
    // assessment remains an explicit offline calibration tool.
    result.diagnostic.assess_proof_noise = false;
    result.diagnostic.require_zero_payload_replay =
        command.profile != "quick";
    return result;
}

SealParameters process_client_seal_parameters(
    const ProcessProfile &selected, const Options &options,
    BaseSealParameterVersion version = BaseSealParameterVersion::Current) {
    // Context bundles retain the setup key-generation policy even though the
    // client bundle itself contains no Galois keys. Reconstruct that policy
    // from the fixed profile without compiling its million-gate circuit.
    const bool generate_galois_keys =
        benchmark_payload_profile(selected.name).rotate_gates != 0;
    return diagnostic_seal_parameters(options.diagnostic.slots,
                                      selected.workload_kind,
                                      generate_galois_keys, version);
}

void make_private_directory(const std::filesystem::path &path) {
    std::error_code error;
    if (!std::filesystem::create_directory(path, error) || error) {
        throw std::runtime_error("failed to create private run directory: " +
                                 path.string());
    }
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace, error);
    if (error) {
        throw std::runtime_error("failed to protect run directory: " +
                                 path.string());
    }
}

void create_process_run_tree(const std::filesystem::path &root) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(root, error);
    if (!error && status.type() != std::filesystem::file_type::not_found) {
        throw std::invalid_argument(
            "setup requires a run directory that does not already exist");
    }
    error.clear();
    make_private_directory(root);
    make_private_directory(root / "shared");
    make_private_directory(root / "shared" / "transcript");
    make_private_directory(root / "shared" / "report");
    make_private_directory(root / "client");
    make_private_directory(root / "client" / "preprocessing");
    make_private_directory(root / "client" / "work");
    make_private_directory(root / "server");
    make_private_directory(root / "server" / "preprocessing");
    make_private_directory(root / "server" / "work");
}

class ProcessWriter {
  public:
    void u64(std::uint64_t value) {
        for (std::size_t byte = 0; byte < 8; ++byte) {
            bytes_.push_back(static_cast<std::uint8_t>(
                (value >> (8U * byte)) & 0xffU));
        }
    }

    void bytes(std::span<const std::uint8_t> value) {
        u64(value.size());
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    void text(std::string_view value) {
        bytes(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(value.data()),
            value.size()));
    }

    void digest(const Digest &value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    void basefold_digest(const basefold::Digest &value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    void boolean(bool value) { u64(value ? 1U : 0U); }

    std::vector<std::uint8_t> finish() && {
        return std::move(bytes_);
    }

  private:
    std::vector<std::uint8_t> bytes_;
};

class ProcessReader {
  public:
    explicit ProcessReader(std::span<const std::uint8_t> input)
        : input_(input) {}

    std::uint64_t u64(std::string_view description) {
        require_bytes(8, description);
        std::uint64_t value = 0;
        for (std::size_t byte = 0; byte < 8; ++byte) {
            value |= static_cast<std::uint64_t>(input_[position_ + byte])
                     << (8U * byte);
        }
        position_ += 8;
        return value;
    }

    std::size_t size(std::size_t maximum,
                     std::string_view description) {
        const std::uint64_t value = u64(description);
        if (value > maximum ||
            value > std::numeric_limits<std::size_t>::max()) {
            throw std::invalid_argument(std::string(description) +
                                        " exceeds its decode limit");
        }
        return static_cast<std::size_t>(value);
    }

    std::span<const std::uint8_t> bytes(std::size_t maximum,
                                        std::string_view description) {
        const std::size_t count = size(maximum, description);
        require_bytes(count, description);
        const auto result = input_.subspan(position_, count);
        position_ += count;
        return result;
    }

    std::string text(std::size_t maximum,
                     std::string_view description) {
        const auto value = bytes(maximum, description);
        return std::string(reinterpret_cast<const char *>(value.data()),
                           value.size());
    }

    Digest digest(std::string_view description) {
        require_bytes(Digest{}.size(), description);
        Digest value{};
        std::copy_n(input_.begin() +
                        static_cast<std::ptrdiff_t>(position_),
                    value.size(), value.begin());
        position_ += value.size();
        return value;
    }

    basefold::Digest basefold_digest(std::string_view description) {
        require_bytes(basefold::Digest{}.size(), description);
        basefold::Digest value{};
        std::copy_n(input_.begin() +
                        static_cast<std::ptrdiff_t>(position_),
                    value.size(), value.begin());
        position_ += value.size();
        return value;
    }

    void finish() const {
        if (position_ != input_.size()) {
            throw std::invalid_argument("setup.bin has trailing data");
        }
    }

  private:
    void require_bytes(std::size_t count,
                       std::string_view description) const {
        if (position_ > input_.size() ||
            count > input_.size() - position_) {
            throw std::invalid_argument(std::string(description) +
                                        " is truncated");
        }
    }

    std::span<const std::uint8_t> input_;
    std::size_t position_ = 0;
};

void encode_replay_artifact_peak(ProcessWriter &writer,
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

void encode_replay_storage_profile(
    ProcessWriter &writer,
    const PayloadCheckpointStorageProfile &profile) {
    writer.u64(profile.checkpoint_layers.size());
    for (const std::size_t layer : profile.checkpoint_layers) {
        writer.u64(layer);
    }
    writer.u64(profile.checkpoint_metadata_bytes);
    writer.u64(profile.checkpoint_metadata_validation_buffer_bytes);
    writer.u64(profile.checkpoint_bytes);
    writer.u64(profile.chunk_ciphertexts);
    writer.u64(
        profile.dense_multiplication_alias_cache_peak_resident_bytes);
    writer.u64(profile.retained_output_peak_resident_bytes);
    encode_replay_artifact_peak(writer, profile.forward_artifact_peak);
    writer.u64(profile.forward_peak_live_scratch_bytes);
    writer.u64(profile.proof_ingress_artifact_bytes_upper_bound);
    writer.u64(profile.proof_ingress_peak_live_scratch_bytes);
    writer.u64(profile.proof_ingress_peak_resident_bytes);
    writer.u64(profile.post_replay_consumer_artifact_bytes_upper_bound);
    writer.u64(profile.post_replay_consumer_peak_live_scratch_bytes);
    writer.u64(profile.peak_live_scratch_bytes);
    writer.u64(profile.peak_resident_bytes);
    writer.u64(profile.initial_forward_work_units);
    writer.u64(profile.replay_work_units);
    writer.u64(profile.cumulative_work_units);
    writer.boolean(profile.live_scratch_feasible);
    writer.boolean(profile.resident_feasible);
    writer.boolean(profile.recomputation_feasible);
}

Digest base_replay_plan_digest(
    const PayloadCheckpointReplayPlan &plan) {
    ProcessWriter writer;
    writer.text("LaminateImpl/BaseCheckpointReplayPlan/v2");
    encode_replay_storage_profile(writer, plan.full_trace_reference);
    encode_replay_storage_profile(writer, plan.selected);
    writer.u64(plan.reverse_gkr_segments.size());
    for (const PayloadReplaySegment &segment :
         plan.reverse_gkr_segments) {
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
        writer.u64(segment.post_replay_consumer_peak_live_scratch_bytes);
        encode_replay_artifact_peak(writer, segment.artifact_peak);
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
    return sha256(std::move(writer).finish());
}

struct ProcessSetupRecord {
    std::string variant;
    std::string profile;
    std::string git_commit;
    std::string build_type;
    std::string seal_acceleration;
    Digest run_id{};
    Digest public_setup_digest{};
    Digest payload_digest{};
    Digest layered_digest{};
    Digest circuit_digest{};
    Digest schedule_digest{};
    std::optional<gates::GateTableVerifierKey> gate_mle_verifier;
    std::string proof_schedule_policy;
    std::size_t proof_ingress_rns_limbs = 0;
    std::size_t fresh_modulus_product_bits = 0;
    HostResourceBudget host_budget;
    PayloadCheckpointReplayBudgets replay_budgets;
    Digest replay_plan_digest{};
    std::uint64_t client_peak_resident_bytes = 0;
    BaseWireDecodeLimits client_wire_limits;
    std::uint64_t server_bytes = 0;
    Digest server_digest{};
    std::uint64_t client_context_bytes = 0;
    Digest client_context_digest{};
    std::uint64_t client_static_bytes = 0;
    Digest client_static_digest{};

    bool operator==(const ProcessSetupRecord &) const = default;
};

void encode_gate_mle_verifier(
    ProcessWriter &writer,
    const std::optional<gates::GateTableVerifierKey> &key) {
    writer.u64(key.has_value() ? 1U : 0U);
    if (!key) {
        return;
    }
    writer.u64(static_cast<std::uint64_t>(key->layout.table_set));
    writer.u64(key->basefold_parameters.log_rate);
    writer.u64(key->basefold_parameters.num_queries);
    writer.u64(key->foldable_parameters.num_queries);
    writer.digest(key->layout_digest);
    writer.u64(key->layout.tables.size());
    for (const gates::GateTableDescriptor &table : key->layout.tables) {
        writer.u64(table.layer_index);
        writer.u64(static_cast<std::uint64_t>(table.kind));
        writer.u64(table.selector);
        writer.u64(table.local_variables);
        writer.u64(table.support_size);
    }
    writer.u64(key->layout.wide_layers.size());
    for (const auto &layer : key->layout.wide_layers) {
        writer.u64(layer.layer_index);
        writer.u64(layer.node_count);
        const auto &d = layer.dimensions;
        for (auto value : {d.slots, d.input_width, d.output_width,
             d.internal_width, d.row_width, d.source_width, d.mask_width,
             d.internal_scalars, d.uniform_edge_domain, d.mask_edge_domain,
             d.uniform_constant_domain, d.slot_constant_domain,
             d.dictionary_domain}) writer.u64(value);
        writer.digest(layer.program_digest);
    }
    writer.u64(key->layout.wide_masks.slots);
    writer.u64(key->layout.wide_masks.mask_count);
    writer.u64(key->layout.wide_masks.mask_width);
    writer.digest(key->layout.wide_masks.dictionary_digest);
    writer.u64(key->tables.size());
    for (const gates::SparseTableCommitment &table : key->tables) {
        writer.u64(table.message_size);
        writer.u64(table.shard_size);
        writer.u64(table.shard_count);
        writer.u64(table.logical_width);
        writer.u64(table.physical_width);
        writer.basefold_digest(table.root);
        writer.u64(table.foldable ? 1U : 0U);
        if (table.foldable) {
            writer.u64(table.foldable->m);
            writer.u64(table.foldable->width);
            writer.u64(table.foldable->hierarchy_version);
        }
        writer.u64(table.wide_block_offset.has_value());
        if (table.wide_block_offset) writer.u64(*table.wide_block_offset);
    }
    writer.u64(key->wide_public_commitment.has_value());
    if (key->wide_public_commitment) {
        const auto &metadata = *key->wide_public_commitment;
        writer.basefold_digest(metadata.root);
        writer.u64(metadata.m);
        writer.u64(metadata.width);
        writer.u64(metadata.hierarchy_version);
    }
}

std::optional<gates::GateTableVerifierKey>
decode_gate_mle_verifier(ProcessReader &reader) {
    constexpr std::size_t kMaximumTables = 256;
    constexpr std::size_t kMaximumGeometry = std::size_t{1} << 40U;
    const std::uint64_t present = reader.u64("GateMLE verifier presence");
    if (present > 1U) {
        throw std::invalid_argument(
            "GateMLE verifier presence is noncanonical");
    }
    if (present == 0U) {
        return std::nullopt;
    }
    const std::uint64_t table_set = reader.u64("GateMLE table set");
    if (table_set >
        static_cast<std::uint64_t>(gates::GateTableSet::Laned)) {
        throw std::invalid_argument("GateMLE table set is invalid");
    }
    gates::GateTableVerifierKey result;
    result.layout.table_set =
        static_cast<gates::GateTableSet>(table_set);
    result.basefold_parameters.log_rate =
        reader.size(64, "GateMLE BaseFold log rate");
    result.basefold_parameters.num_queries =
        reader.size(1024, "GateMLE BaseFold query count");
    result.foldable_parameters.num_queries =
        reader.size(1024, "GateMLE foldable query count");
    result.layout_digest = reader.digest("GateMLE layout digest");
    const std::size_t descriptor_count =
        reader.size(kMaximumTables, "GateMLE descriptor count");
    result.layout.tables.reserve(descriptor_count);
    for (std::size_t index = 0; index < descriptor_count; ++index) {
        const std::size_t layer_index = reader.size(
            kMaximumTables, "GateMLE layer index");
        const std::uint64_t kind = reader.u64("GateMLE table kind");
        if (kind > static_cast<std::uint64_t>(
                       gates::GateTableKind::WideMaskDictionary)) {
            throw std::invalid_argument("GateMLE table kind is invalid");
        }
        result.layout.tables.push_back(gates::GateTableDescriptor{
            .layer_index = layer_index,
            .kind = static_cast<gates::GateTableKind>(kind),
            .selector = reader.size(kMaximumTables,
                                    "GateMLE table selector"),
            .local_variables = reader.size(128,
                                           "GateMLE local variables"),
            .support_size = reader.size(kMaximumGeometry,
                                        "GateMLE support size"),
        });
    }
    const auto layers = reader.size(kMaximumTables, "Wide layer count");
    result.layout.wide_layers.reserve(layers);
    for (std::size_t index = 0; index < layers; ++index) {
        gates::WideLayerMetadata layer;
        layer.layer_index = reader.size(kMaximumTables, "Wide layer index");
        layer.node_count = reader.size(kMaximumGeometry, "Wide node count");
        auto &d = layer.dimensions;
        for (auto *value : {&d.slots, &d.input_width, &d.output_width,
             &d.internal_width, &d.row_width, &d.source_width, &d.mask_width,
             &d.internal_scalars, &d.uniform_edge_domain, &d.mask_edge_domain,
             &d.uniform_constant_domain, &d.slot_constant_domain,
             &d.dictionary_domain}) {
            *value = reader.size(std::numeric_limits<std::size_t>::max(),
                                 "Wide Boolean domain");
            if (!std::has_single_bit(*value))
                throw std::invalid_argument("invalid Wide Boolean domain");
        }
        layer.program_digest = reader.digest("Wide program digest");
        result.layout.wide_layers.push_back(layer);
    }
    result.layout.wide_masks.slots = reader.size(kMaximumGeometry, "Wide slots");
    result.layout.wide_masks.mask_count = reader.size(kMaximumGeometry, "Wide masks");
    result.layout.wide_masks.mask_width = reader.size(kMaximumGeometry, "Wide mask width");
    result.layout.wide_masks.dictionary_digest = reader.digest("Wide dictionary digest");
    const std::size_t table_count =
        reader.size(kMaximumTables, "GateMLE commitment count");
    result.tables.reserve(table_count);
    for (std::size_t index = 0; index < table_count; ++index) {
        result.tables.push_back(gates::SparseTableCommitment{
            .message_size = reader.size(kMaximumGeometry,
                                        "GateMLE message size"),
            .shard_size = reader.size(kMaximumGeometry,
                                      "GateMLE shard size"),
            .shard_count = reader.size(kMaximumGeometry,
                                       "GateMLE shard count"),
            .logical_width = reader.size(kMaximumGeometry,
                                         "GateMLE logical width"),
            .physical_width = reader.size(kMaximumGeometry,
                                          "GateMLE physical width"),
            .root = reader.basefold_digest("GateMLE BaseFold root"),
        });
        const auto generic = reader.u64("foldable commitment presence");
        if (generic > 1) throw std::invalid_argument("invalid foldable presence");
        if (generic) {
            basefold::foldable::Metadata metadata;
            metadata.root = result.tables.back().root;
            metadata.m = reader.size(std::size_t{1} << basefold::foldable::kMaxVariables,
                                      "foldable message length");
            metadata.width = reader.size(256, "foldable width");
            metadata.hierarchy_version = reader.u64("foldable hierarchy version");
            result.tables.back().foldable = metadata;
        }
        const auto block = reader.u64("Wide block presence");
        if (block > 1) throw std::invalid_argument("invalid Wide block presence");
        if (block) result.tables.back().wide_block_offset =
            reader.size(kMaximumGeometry, "Wide block offset");
    }
    const auto shared = reader.u64("Wide public commitment presence");
    if (shared > 1) throw std::invalid_argument("invalid Wide public presence");
    if (shared) {
        basefold::foldable::Metadata metadata;
        metadata.root = reader.basefold_digest("Wide public root");
        metadata.m = reader.size(kMaximumGeometry, "Wide public message size");
        metadata.width = reader.size(256, "Wide public width");
        metadata.hierarchy_version = reader.u64("Wide public hierarchy version");
        result.wide_public_commitment = metadata;
    }
    if (!gates::valid_wide_public_index(result))
        throw std::invalid_argument("invalid Wide public index layout");
    return result;
}

std::uint64_t require_process_client_preprocessing_bound(
    const Options &options, const ProcessSetupRecord &stored) {
    const std::uint64_t total = checked_add_u64(
        stored.client_context_bytes, stored.client_static_bytes,
        "client preprocessing size");
    const std::uint64_t limit = diagnostic_scaled_bytes(
        options.diagnostic.slots, std::uint64_t{2} << 30U,
        std::uint64_t{1} << 28U,
        "diagnostic client preprocessing upper");
    if (total > limit) {
        throw std::runtime_error(
            "client preprocessing exceeds the selected profile bound");
    }
    return total;
}

protocol::BaseClientStaticSetupDecodeLimits
process_client_static_decode_limits(
    const ProcessProfile &selected, const Options &options,
    const ProcessSetupRecord &stored) {
    const std::size_t maximum_layer_gates = 2U * std::bit_ceil(
        std::max(selected.middle_width, selected.inputs));
    return protocol::BaseClientStaticSetupDecodeLimits{
        .max_artifact_bytes = checked_size(
            stored.client_static_bytes,
            "client static preprocessing bytes"),
        .max_slots = options.diagnostic.slots,
        .max_payload_plaintexts = 64,
        .max_payload_gates = kBenchmarkPayloadOperationCount,
        .max_payload_outputs = kBenchmarkDiamondInputCiphertexts,
        .max_layers = 64,
        .max_layer_gates = maximum_layer_gates,
        .max_affine_terms = 4U * kBenchmarkPayloadOperationCount,
        .max_storage_entries = std::max(128U * maximum_layer_gates,
            stored.gate_mle_verifier && stored.gate_mle_verifier->wide_public_commitment
                ? stored.gate_mle_verifier->wide_public_commitment->m : std::size_t{0}),
    };
}

void require_process_client_profile_geometry(
    const ProcessProfile &selected,
    const protocol::CertifiedBaseClientSetup<SealBackend> &client) {
    const PayloadCircuit &payload = client.payload();
    const LayeredCircuit &circuit = client.circuit();
    const BenchmarkPayloadProfile profile =
        benchmark_payload_profile(selected.name);
    const PayloadStats stats = analyze(payload);
    if (payload.shape != PayloadShape::wide(kDiagnosticDefaultSlots) ||
        circuit.shape != payload.shape ||
        payload.input_count != selected.inputs ||
        payload.outputs.size() != kBenchmarkDiamondOutputCiphertexts ||
        payload.gates.size() != selected.operation_count ||
        stats.add_gates != profile.add_gates ||
        stats.add_plain_gates != profile.add_plain_gates ||
        stats.mul_gates != profile.mul_gates ||
        circuit.payload_input_count != selected.inputs ||
        circuit.payload_output_count !=
            kBenchmarkDiamondOutputCiphertexts ||
        circuit.proof_multiplication_depth !=
            selected.multiplicative_depth) {
        throw std::runtime_error(
            "client static preprocessing differs from the selected "
            "benchmark profile");
    }
}

void encode_host_resource_budget(ProcessWriter &writer,
                                   const HostResourceBudget &budget) {
    writer.u64(budget.observed_available_disk_bytes);
    writer.u64(budget.observed_physical_ram_bytes);
    writer.u64(budget.max_live_disk_bytes);
    writer.u64(budget.max_resident_ram_bytes);
}

HostResourceBudget decode_host_resource_budget(ProcessReader &reader) {
    return {
        .observed_available_disk_bytes =
            reader.u64("observed host disk bytes"),
        .observed_physical_ram_bytes =
            reader.u64("observed host physical RAM bytes"),
        .max_live_disk_bytes = reader.u64("host live-disk budget"),
        .max_resident_ram_bytes = reader.u64("host resident budget"),
    };
}

void encode_process_replay_budgets(
    ProcessWriter &writer,
    const PayloadCheckpointReplayBudgets &budgets) {
    writer.u64(budgets.max_live_scratch_bytes);
    writer.u64(budgets.max_resident_ciphertext_bytes);
    writer.u64(budgets.max_ciphertexts_per_chunk);
    writer.u64(budgets.max_recomputation_factor.numerator);
    writer.u64(budgets.max_recomputation_factor.denominator);
    writer.u64(budgets.reserved_live_scratch_bytes);
    writer.u64(budgets.reserved_resident_bytes);
    writer.u64(static_cast<std::uint64_t>(budgets.selection_objective));
    writer.u64(
        budgets.post_replay_consumer_artifact_bytes_by_reduction.size());
    for (const std::uint64_t bytes :
         budgets.post_replay_consumer_artifact_bytes_by_reduction) {
        writer.u64(bytes);
    }
}

PayloadCheckpointReplayBudgets decode_process_replay_budgets(
    ProcessReader &reader) {
    PayloadCheckpointReplayBudgets result{
        .max_live_scratch_bytes =
            reader.u64("replay live-disk budget"),
        .max_resident_ciphertext_bytes =
            reader.u64("replay resident budget"),
        .max_ciphertexts_per_chunk =
            reader.size(std::size_t{1} << 20U,
                        "replay ciphertext chunk"),
        .max_recomputation_factor = {
            reader.u64("recomputation numerator"),
            reader.u64("recomputation denominator")},
        .reserved_live_scratch_bytes =
            reader.u64("reserved replay disk bytes"),
        .reserved_resident_bytes =
            reader.u64("reserved replay resident bytes"),
    };
    const std::uint64_t objective =
        reader.u64("replay selection objective");
    if (objective > static_cast<std::uint64_t>(
                        PayloadCheckpointSelectionObjective::
                            MinimumReplayWork)) {
        throw std::invalid_argument(
            "setup.bin replay selection objective is invalid");
    }
    result.selection_objective =
        static_cast<PayloadCheckpointSelectionObjective>(objective);
    const std::size_t artifact_count =
        reader.size(128, "post-replay artifact bound count");
    result.post_replay_consumer_artifact_bytes_by_reduction.reserve(
        artifact_count);
    for (std::size_t index = 0; index < artifact_count; ++index) {
        result.post_replay_consumer_artifact_bytes_by_reduction.push_back(
            reader.u64("post-replay artifact bound"));
    }
    return result;
}

void encode_process_wire_limits(ProcessWriter &writer,
                                const BaseWireDecodeLimits &limits) {
    writer.u64(limits.max_message_bytes);
    writer.u64(limits.max_ciphertexts);
    writer.u64(limits.max_ciphertext_bytes);
    writer.u64(limits.max_total_ciphertext_bytes);
    writer.u64(limits.max_claim_coordinates);
    writer.u64(limits.max_proof_bytes);
    writer.u64(limits.max_reductions);
    writer.u64(limits.max_rounds_per_reduction);
    writer.u64(limits.max_gate_proof_rounds);
    writer.u64(limits.max_partial_gate_values);
    writer.u64(limits.max_gate_claims);
    writer.u64(limits.max_gate_target_values);
    writer.u64(limits.max_basefold_queries);
    writer.u64(limits.max_merkle_path_digests);
    writer.u64(limits.max_total_field_elements);
    writer.u64(limits.max_total_digests);
}

BaseWireDecodeLimits decode_process_wire_limits(ProcessReader &reader) {
    constexpr std::size_t maximum =
        std::numeric_limits<std::size_t>::max();
    BaseWireDecodeLimits result{
        .max_message_bytes = reader.size(maximum, "wire message bytes"),
        .max_ciphertexts = reader.size(maximum, "wire ciphertext count"),
        .max_ciphertext_bytes =
            reader.size(maximum, "wire ciphertext bytes"),
        .max_total_ciphertext_bytes =
            reader.size(maximum, "wire total ciphertext bytes"),
        .max_claim_coordinates =
            reader.size(maximum, "wire claim coordinates"),
        .max_proof_bytes = reader.size(maximum, "wire proof bytes"),
        .max_reductions = reader.size(maximum, "wire reductions"),
        .max_rounds_per_reduction =
            reader.size(maximum, "proof rounds per reduction"),
        .max_gate_proof_rounds =
            reader.size(maximum, "structured GateMLE proof rounds"),
        .max_partial_gate_values =
            reader.size(maximum, "wire partial gate values"),
        .max_gate_claims = reader.size(maximum, "wire gate claims"),
        .max_gate_target_values =
            reader.size(maximum, "wire gate target values"),
        .max_basefold_queries =
            reader.size(maximum, "wire BaseFold queries"),
        .max_merkle_path_digests =
            reader.size(maximum, "wire Merkle path digests"),
        .max_total_field_elements =
            reader.size(maximum, "wire total field elements"),
        .max_total_digests =
            reader.size(maximum, "wire total digests"),
    };
    constexpr std::size_t kMaximumClientMessageBytes =
        std::size_t{8} << 30U;
    if (result.max_message_bytes == 0 ||
        result.max_message_bytes > kMaximumClientMessageBytes ||
        result.max_ciphertexts == 0 ||
        result.max_ciphertexts > (std::size_t{1} << 20U) ||
        result.max_ciphertext_bytes == 0 ||
        result.max_ciphertext_bytes > (std::size_t{16} << 20U) ||
        result.max_total_ciphertext_bytes >
            kMaximumClientMessageBytes ||
        result.max_claim_coordinates > 512 ||
        result.max_proof_bytes > kMaximumClientMessageBytes ||
        result.max_reductions > 128 ||
        result.max_rounds_per_reduction > 512 ||
        result.max_gate_proof_rounds > 512 ||
        result.max_partial_gate_values > (std::size_t{1} << 20U) ||
        result.max_gate_claims > (std::size_t{1} << 20U) ||
        result.max_gate_target_values > (std::size_t{1} << 24U) ||
        result.max_basefold_queries > 1024 ||
        result.max_merkle_path_digests > 512 ||
        result.max_total_field_elements > (std::size_t{1} << 31U) ||
        result.max_total_digests > (std::size_t{1} << 31U)) {
        throw std::invalid_argument(
            "setup.bin client wire limits exceed the committed hard caps");
    }
    return result;
}

std::vector<std::uint8_t> encode_process_setup(
    const ProcessSetupRecord &record) {
    ProcessWriter writer;
    writer.text(kProcessSetupDomain);
    writer.text(record.variant);
    writer.text(record.profile);
    writer.text(record.git_commit);
    writer.text(record.build_type);
    writer.text(record.seal_acceleration);
    writer.digest(record.run_id);
    writer.digest(record.public_setup_digest);
    writer.digest(record.payload_digest);
    writer.digest(record.layered_digest);
    writer.digest(record.circuit_digest);
    writer.digest(record.schedule_digest);
    encode_gate_mle_verifier(writer, record.gate_mle_verifier);
    writer.text(record.proof_schedule_policy);
    writer.u64(record.proof_ingress_rns_limbs);
    writer.u64(record.fresh_modulus_product_bits);
    encode_host_resource_budget(writer, record.host_budget);
    encode_process_replay_budgets(writer, record.replay_budgets);
    writer.digest(record.replay_plan_digest);
    writer.u64(record.client_peak_resident_bytes);
    encode_process_wire_limits(writer, record.client_wire_limits);
    writer.u64(record.server_bytes);
    writer.digest(record.server_digest);
    writer.u64(record.client_context_bytes);
    writer.digest(record.client_context_digest);
    writer.u64(record.client_static_bytes);
    writer.digest(record.client_static_digest);
    return std::move(writer).finish();
}

ProcessSetupRecord decode_process_setup(
    std::span<const std::uint8_t> encoded) {
    if (encoded.size() > kProcessMaximumSetupBytes) {
        throw std::invalid_argument("setup.bin exceeds its decode limit");
    }
    ProcessReader reader(encoded);
    if (reader.text(128, "setup format") != kProcessSetupDomain) {
        throw std::invalid_argument("setup.bin has an unsupported format");
    }
    ProcessSetupRecord result;
    result.variant = reader.text(16, "setup variant");
    result.profile = reader.text(kProcessMaximumProfileBytes, "setup profile");
    result.git_commit = reader.text(128, "setup git commit");
    result.build_type = reader.text(64, "setup build type");
    result.seal_acceleration = reader.text(128, "setup SEAL acceleration");
    result.run_id = reader.digest("setup run id");
    result.public_setup_digest = reader.digest("public setup digest");
    result.payload_digest = reader.digest("payload digest");
    result.layered_digest = reader.digest("layered digest");
    result.circuit_digest = reader.digest("circuit digest");
    result.schedule_digest = reader.digest("schedule digest");
    result.gate_mle_verifier = decode_gate_mle_verifier(reader);
    result.proof_schedule_policy =
        reader.text(128, "proof schedule policy");
    result.proof_ingress_rns_limbs =
        reader.size(64, "proof ingress RNS limb count");
    result.fresh_modulus_product_bits =
        reader.size(4096, "fresh modulus product bits");
    result.host_budget = decode_host_resource_budget(reader);
    result.replay_budgets = decode_process_replay_budgets(reader);
    result.replay_plan_digest = reader.digest("replay plan digest");
    result.client_peak_resident_bytes =
        reader.u64("client peak resident reserve");
    result.client_wire_limits = decode_process_wire_limits(reader);
    result.server_bytes = reader.u64("server preprocessing size");
    result.server_digest = reader.digest("server preprocessing digest");
    result.client_context_bytes =
        reader.u64("client FHE-context preprocessing size");
    result.client_context_digest =
        reader.digest("client FHE-context preprocessing digest");
    result.client_static_bytes =
        reader.u64("client static verifier preprocessing size");
    result.client_static_digest =
        reader.digest("client static verifier preprocessing digest");
    reader.finish();
    if (encode_process_setup(result) !=
        std::vector<std::uint8_t>(encoded.begin(), encoded.end())) {
        throw std::invalid_argument("setup.bin is not canonical");
    }
    return result;
}

std::vector<std::uint8_t> read_bounded_file(
    const std::filesystem::path &path, std::uint64_t maximum_bytes) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("required regular file is absent: " +
                                 path.string());
    }
    const std::uintmax_t count = std::filesystem::file_size(path, error);
    if (error || count > maximum_bytes ||
        count > std::numeric_limits<std::size_t>::max() ||
        count > static_cast<std::uintmax_t>(
                    std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("file size is outside its bound: " +
                                 path.string());
    }
    std::vector<std::uint8_t> result(static_cast<std::size_t>(count));
    std::ifstream input(path, std::ios::binary);
    input.read(reinterpret_cast<char *>(result.data()),
               static_cast<std::streamsize>(result.size()));
    if (!input || input.peek() != std::ifstream::traits_type::eof()) {
        throw std::runtime_error("failed to read exact file: " +
                                 path.string());
    }
    return result;
}

void publish_private_file(const std::filesystem::path &path,
                          std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        throw std::invalid_argument("cannot publish an empty artifact");
    }
    const std::filesystem::path temporary = path.string() + ".partial";
    if (std::filesystem::exists(path) ||
        std::filesystem::exists(temporary)) {
        throw std::invalid_argument("refusing to replace artifact: " +
                                    path.string());
    }
    write_private_bundle(temporary, bytes);
    std::error_code error;
    std::filesystem::rename(temporary, path, error);
    if (error) {
        std::filesystem::remove(temporary);
        throw std::runtime_error("failed to publish artifact: " +
                                 path.string());
    }
}

void publish_process_run_binding(const ProcessCommand &command,
                                 std::string_view run_id) {
    const std::string contents =
        "format=laminate-benchmark-run-v1\nrun.variant=" + command.variant +
        "\nrun.profile=" + command.profile + "\nrun.id=" +
        std::string(run_id) + "\n";
    publish_private_file(
        command.run_directory / "shared" / "run-binding.txt",
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(contents.data()),
            contents.size()));
}

Digest random_digest() {
    std::array<std::uint8_t, 64> entropy{};
    std::random_device source;
    for (std::uint8_t &byte : entropy) {
        byte = static_cast<std::uint8_t>(source());
    }
    return sha256(entropy);
}

std::int64_t unix_milliseconds() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
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

/// An append-only activity record whose advisory lock is held for the whole
/// role lifetime. The lock, rather than a PID or a timestamp, is the evidence
/// that status uses to distinguish a live process from an interrupted one.
/// Creating the file with O_EXCL also makes each role a one-attempt operation.
class RoleActivity {
  public:
    RoleActivity(std::filesystem::path path, std::string_view role)
        : path_(std::move(path)), role_(role),
          uncaught_on_entry_(std::uncaught_exceptions()),
          next_heartbeat_(std::chrono::steady_clock::now()) {
        descriptor_ = ::open(path_.c_str(),
                             O_WRONLY | O_APPEND | O_CREAT | O_EXCL |
                                 O_CLOEXEC,
                             S_IRUSR | S_IWUSR);
        if (descriptor_ < 0) {
            throw std::runtime_error(
                "role activity file already exists or cannot be created: " +
                path_.string());
        }
        if (::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            const int saved_errno = errno;
            ::close(descriptor_);
            descriptor_ = -1;
            ::unlink(path_.c_str());
            throw std::system_error(
                saved_errno, std::generic_category(),
                "failed to lock role activity file");
        }
        try {
            append_required("start", "starting");
        } catch (...) {
            ::flock(descriptor_, LOCK_UN);
            ::close(descriptor_);
            descriptor_ = -1;
            ::unlink(path_.c_str());
            throw;
        }
    }

    RoleActivity(const RoleActivity &) = delete;
    RoleActivity &operator=(const RoleActivity &) = delete;

    ~RoleActivity() {
        if (descriptor_ < 0) {
            return;
        }
        if (!complete_) {
            append_best_effort(
                "stop",
                std::uncaught_exceptions() > uncaught_on_entry_
                    ? "exception"
                    : "stopped_without_result");
        }
        ::flock(descriptor_, LOCK_UN);
        ::close(descriptor_);
    }

    void transition(std::string_view stage) noexcept {
        stage_ = std::string(stage);
        append_best_effort("stage", stage_);
        next_heartbeat_ = std::chrono::steady_clock::now() +
                          std::chrono::seconds(30);
    }

    void heartbeat() noexcept {
        const auto now = std::chrono::steady_clock::now();
        if (now < next_heartbeat_) {
            return;
        }
        append_best_effort("heartbeat", stage_);
        next_heartbeat_ = now + std::chrono::seconds(30);
    }

    void mark_complete() noexcept {
        if (complete_) {
            return;
        }
        complete_ = true;
        stage_ = "complete";
        append_best_effort("stop", stage_);
    }

  private:
    std::string line(std::string_view event,
                     std::string_view stage) const {
        std::ostringstream output;
        output << '{'
               << "\"schema\":\"laminate-role-activity-v1\","
               << "\"role\":" << json_string(role_) << ','
               << "\"event\":" << json_string(event) << ','
               << "\"stage\":" << json_string(stage) << ','
               << "\"pid\":" << static_cast<std::uint64_t>(::getpid())
               << ",\"unix_ms\":" << unix_milliseconds() << "}\n";
        return output.str();
    }

    void append_required(std::string_view event,
                         std::string_view stage) {
        const std::string value = line(event, stage);
        std::size_t written = 0;
        while (written != value.size()) {
            const ssize_t count = ::write(
                descriptor_, value.data() + written,
                value.size() - written);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::system_error(
                    count < 0 ? errno : EIO, std::generic_category(),
                    "failed to append role activity");
            }
            written += static_cast<std::size_t>(count);
        }
    }

    void append_best_effort(std::string_view event,
                            std::string_view stage) noexcept {
        if (logging_failed_) {
            return;
        }
        try {
            append_required(event, stage);
        } catch (...) {
            logging_failed_ = true;
            std::cerr << role_
                      << ": warning: activity logging failed; protocol "
                         "execution continues\n";
        }
    }

    std::filesystem::path path_;
    std::string role_;
    int descriptor_ = -1;
    int uncaught_on_entry_ = 0;
    std::string stage_ = "starting";
    std::chrono::steady_clock::time_point next_heartbeat_;
    bool logging_failed_ = false;
    bool complete_ = false;
};

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
    std::uint64_t selected = 0;
    input >> selected;
    if (!input || input.peek() != std::char_traits<char>::eof()) {
        return std::nullopt;
    }
    return selected;
}

void emit_timing_pair(const Record &record, std::string_view prefix,
                      const Timing &timing) {
    record.real(std::string(prefix) + ".wall_ms", timing.wall_ms);
    record.real(std::string(prefix) + ".cpu_ms", timing.cpu_ms);
}

void emit_process_identity(const Record &record,
                           const ProcessCommand &command,
                           const ProcessSetupRecord &setup) {
    const SystemInfo system = system_info();
    record.text("run.variant", command.variant);
    record.text("run.profile", command.profile);
    record.text("run.id", digest_hex(setup.run_id));
    record.text("protocol.gkr_claim_transition",
                std::string(gkr::kGkrClaimTransition));
    record.text("protocol.gkr_multiplication",
                std::string(gkr::kGkrMultiplicationReduction));
    record.text("environment.git_commit", setup.git_commit);
    record.text("environment.git_dirty",
                LAMINATE_BASE_CHECKPOINT_GIT_DIRTY);
    record.text("environment.build_type", setup.build_type);
    record.text("environment.compiler", LAMINATE_COMPILER);
    record.text("environment.seal_version", LAMINATE_SEAL_VERSION);
    record.text("environment.seal_acceleration", setup.seal_acceleration);
    record.text("environment.sha256_acceleration",
                LAMINATE_SHA256_ACCELERATION);
    record.text("environment.fhe_backend", "seal-bgv");
    record.text("environment.trace_execution",
                "file-backed-checkpoint-replay");
    const auto execution = setup_execution(
        command.action == ProcessAction::Setup);
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

CertifiedHonestPayloadSchedule restore_process_schedule(
    const ProcessSetupRecord &stored, const RunProfile &profile,
    const LayeredCircuit &circuit,
    std::size_t committed_proof_ingress_rns_limbs) {
    if (stored.proof_schedule_policy !=
            kUniformBaseProofIngressPolicyV1 ||
        stored.proof_ingress_rns_limbs !=
            committed_proof_ingress_rns_limbs) {
        throw std::runtime_error(
            "setup.bin does not contain the supported committed Base proof "
            "schedule policy");
    }
    CertifiedHonestPayloadSchedule schedule =
        derive_certified_uniform_honest_base_proof_schedule(
            circuit, profile.seal_parameters.exact_data_primes,
            profile.calibration, stored.proof_ingress_rns_limbs);
    if (schedule.digest() != stored.schedule_digest) {
        throw std::runtime_error(
            "restored schedule differs from immutable setup.bin");
    }
    return schedule;
}

PublicSetup restore_process_public_setup(
    const ProcessSetupRecord &stored, const PayloadCircuit &payload,
    const LayeredCircuit &circuit,
    const CertifiedHonestPayloadSchedule &schedule) {
    if (!stored.gate_mle_verifier) {
        throw std::runtime_error(
            "setup.bin omits the structured GateMLE verifier key");
    }
    PublicSetup result =
        bind_certified_uniform_honest_base_proof_schedule(
            make_outsourced_gate_setup(payload, circuit,
                                       *stored.gate_mle_verifier),
            payload, circuit, schedule);
    if (schedule.digest() != stored.schedule_digest ||
        setup_digest(result) != stored.public_setup_digest) {
        throw std::runtime_error(
            "restored public setup differs from immutable setup.bin");
    }
    return result;
}

PublicSetup restore_process_client_public_setup(
    const ProcessSetupRecord &stored, const PayloadShape &shape,
    std::size_t layer_count,
    std::size_t committed_proof_ingress_rns_limbs) {
    if (stored.proof_schedule_policy !=
            kUniformBaseProofIngressPolicyV1 ||
        stored.proof_ingress_rns_limbs !=
            committed_proof_ingress_rns_limbs ||
        stored.fresh_modulus_product_bits == 0) {
        throw std::runtime_error(
            "setup.bin does not contain the expected Base client policy");
    }
    PublicSetup result;
    if (!stored.gate_mle_verifier) {
        throw std::runtime_error(
            "setup.bin omits the structured GateMLE verifier key");
    }
    result.gate_mle_profile = GateMleProfile::OutsourcedBaseFold;
    result.shape = shape;
    result.layer_count = layer_count;
    result.payload_digest = stored.payload_digest;
    result.layered_digest = stored.layered_digest;
    result.circuit_digest = stored.circuit_digest;
    result.honest_payload_noise_schedule_digest = stored.schedule_digest;
    result.outsourced_gate_mle = *stored.gate_mle_verifier;
    if (setup_digest(result) != stored.public_setup_digest) {
        throw std::runtime_error(
            "restored client public setup differs from immutable "
            "setup.bin");
    }
    return result;
}

void require_gcp_benchmark_build() {
    if (std::string_view(LAMINATE_BASE_CHECKPOINT_GIT_DIRTY) != "false") {
        throw std::runtime_error(
            "GCP benchmark setup requires an executable rebuilt from a "
            "clean git revision");
    }
    if (std::string_view(LAMINATE_BUILD_TYPE) != "Release") {
        throw std::runtime_error(
            "GCP benchmark setup requires CMAKE_BUILD_TYPE=Release");
    }
    if (std::string_view(LAMINATE_SEAL_ACCELERATION) !=
        "intel-hexl-runtime-dispatch") {
        throw std::runtime_error(
            "GCP benchmark setup requires the Intel HEXL SEAL build");
    }
    const SystemInfo::CpuFeatures features = cpu_features();
    if (!features.avx2_available || !features.avx512f_available ||
        !features.avx512dq_available ||
        !features.avx512ifma_available) {
        throw std::runtime_error(
            "GCP benchmark setup requires AVX2, AVX-512F, AVX-512DQ, and "
            "AVX-512IFMA in the guest");
    }
}

int run_build_info() {
    const auto digest = [](std::uint8_t value) {
        Digest result{};
        result.fill(value);
        return result;
    };
    const auto basefold_digest = [](std::uint8_t value) {
        basefold::Digest result{};
        result.fill(value);
        return result;
    };
    const gates::GateTableVerifierKey gate_mle_fixture{
        .layout = gates::GateTableLayout{
            .table_set = gates::GateTableSet::Wide,
            .tables = {gates::GateTableDescriptor{
                .layer_index = 0,
                .kind = gates::GateTableKind::WideLocalUniformEdges,
                .selector = 0,
                .local_variables = 3,
                .support_size = 2,
            }}},
        .basefold_parameters = {},
        .layout_digest = digest(10),
        .tables = {gates::SparseTableCommitment{
            .message_size = 2,
            .shard_size = 2,
            .shard_count = 1,
            .logical_width = 4,
            .physical_width = 4,
            .root = basefold_digest(11),
            .wide_block_offset = 0,
        }},
        .wide_public_commitment = basefold::foldable::Metadata{
            .root = basefold_digest(11), .m = 2, .width = 4},
    };
    const ProcessSetupRecord setup_codec_fixture{
        .variant = "base",
        .profile = "quick",
        .git_commit = "fixture-commit",
        .build_type = "Release",
        .seal_acceleration = "fixture-acceleration",
        .run_id = digest(1),
        .public_setup_digest = digest(2),
        .payload_digest = digest(3),
        .layered_digest = digest(4),
        .circuit_digest = digest(5),
        .schedule_digest = digest(6),
        .gate_mle_verifier = gate_mle_fixture,
        .proof_schedule_policy =
            std::string(kUniformBaseProofIngressPolicyV1),
        .proof_ingress_rns_limbs = 3,
        .fresh_modulus_product_bits = 352,
        .host_budget = {},
        .replay_budgets =
            PayloadCheckpointReplayBudgets{
                .max_live_scratch_bytes = 200'000'000'000ULL,
                .max_resident_ciphertext_bytes = 32'000'000'000ULL,
                .max_ciphertexts_per_chunk = 64,
                .max_recomputation_factor = {5, 2},
                .reserved_live_scratch_bytes = 123,
                .reserved_resident_bytes = 456,
                .selection_objective =
                    PayloadCheckpointSelectionObjective::MinimumStorage,
            },
        .replay_plan_digest = digest(12),
        .client_peak_resident_bytes = 4'000'000'000ULL,
        .client_wire_limits =
            BaseWireDecodeLimits{
                .max_message_bytes = std::size_t{1} << 30U,
                .max_ciphertexts = std::size_t{1} << 16U,
                .max_ciphertext_bytes = std::size_t{1} << 20U,
                .max_total_ciphertext_bytes = std::size_t{1} << 30U,
                .max_claim_coordinates = 64,
                .max_proof_bytes = std::size_t{1} << 30U,
                .max_reductions = 16,
                .max_rounds_per_reduction = 64,
                .max_gate_proof_rounds = 64,
                .max_partial_gate_values = 64,
                .max_gate_claims = 0,
                .max_gate_target_values = 0,
                .max_basefold_queries = 0,
                .max_merkle_path_digests = 0,
                .max_total_field_elements = std::size_t{1} << 20U,
                .max_total_digests = 0,
            },
        .server_bytes = 1234,
        .server_digest = digest(7),
        .client_context_bytes = 5678,
        .client_context_digest = digest(8),
        .client_static_bytes = 9012,
        .client_static_digest = digest(9),
    };
    const HostResourceBudget host_fixture =
        derive_host_resource_budget(500'000'000'000ULL,
                                      256'000'000'000ULL);
    const std::uint64_t client_private =
        base_client_preprocessing_bytes_upper(kDiagnosticDefaultSlots);
    for (const std::string_view profile_name :
         {"quick", "target-balancedLaned", "target-mulHeavyPyramid"}) {
        // The runner invokes build_info before expensive setup. Exercise the
        // persisted codec with every supported name, including target profiles.
        ProcessSetupRecord codec_fixture = setup_codec_fixture;
        codec_fixture.profile = profile_name;
        if (decode_process_setup(encode_process_setup(codec_fixture)) !=
            codec_fixture) {
            throw std::logic_error("Base process setup codec self-check failed");
        }
        const ProcessCommand option_fixture{
            .action = ProcessAction::Setup,
            .variant = "base",
            .profile = std::string(profile_name),
            .run_directory = "/tmp/base-build-info-fixture",
        };
        const Options adaptive_options = process_options(
            option_fixture, process_profile(profile_name), host_fixture);
        if (adaptive_options.diagnostic.max_live_disk_bytes !=
                reserve_role_private_disk(host_fixture, client_private) ||
            adaptive_options.diagnostic
                    .client_private_persistent_disk_bytes != client_private ||
            adaptive_options.diagnostic.checkpoint_selection_objective !=
                PayloadCheckpointSelectionObjective::MinimumReplayWork) {
            throw std::logic_error(
                "Base adaptive resource-budget self-check failed");
        }
    }
    std::cout
        << "format=laminate-base-checkpoint-build-info-v1\n"
        << "protocol.gkr_claim_transition=" << gkr::kGkrClaimTransition << '\n'
        << "protocol.gkr_multiplication=" << gkr::kGkrMultiplicationReduction << '\n'
        << "environment.git_commit="
        << LAMINATE_BASE_CHECKPOINT_GIT_COMMIT << '\n'
        << "environment.git_dirty="
        << LAMINATE_BASE_CHECKPOINT_GIT_DIRTY << '\n'
        << "environment.build_type=" << LAMINATE_BUILD_TYPE << '\n'
        << "environment.seal_acceleration="
        << LAMINATE_SEAL_ACCELERATION << '\n'
        << "environment.sha256_acceleration="
        << LAMINATE_SHA256_ACCELERATION << '\n'
        << "campaign.target-balancedLaned.variants=base\n"
        << "campaign.target-mulHeavyPyramid.variants=base\n"
        << "profile.gate_mle=wide-local-adjoint-foldable\n";
    return 0;
}

ProcessSetupRecord load_process_setup(
    const ProcessCommand &command) {
    const std::filesystem::path path =
        command.run_directory / "shared" / "setup.bin";
    ProcessSetupRecord result = decode_process_setup(
        read_bounded_file(path, kProcessMaximumSetupBytes));
    if (result.variant != command.variant ||
        result.profile != command.profile) {
        throw std::invalid_argument(
            "command variant/profile does not match setup.bin");
    }
    return result;
}

HostResourceBudget require_bound_host_budget(
    const ProcessSetupRecord &setup) {
    if (setup.client_peak_resident_bytes == 0) {
        throw std::invalid_argument(
            "setup.bin omits the modeled client resident peak");
    }
    const HostResourceBudget canonical =
        derive_host_resource_budget(
            setup.host_budget.observed_available_disk_bytes,
            setup.host_budget.observed_physical_ram_bytes);
    if (setup.host_budget != canonical) {
        throw std::invalid_argument(
            "setup.bin contains a noncanonical host budget");
    }
    if (reserve_concurrent_client_ram(
            canonical, setup.client_peak_resident_bytes) !=
        setup.replay_budgets.max_resident_ciphertext_bytes) {
        throw std::invalid_argument(
            "setup.bin does not preserve the host RAM reserve after "
            "charging the concurrent client");
    }
    return canonical;
}

void require_process_build_match(const ProcessSetupRecord &setup) {
    if (setup.git_commit != LAMINATE_BASE_CHECKPOINT_GIT_COMMIT ||
        setup.build_type != LAMINATE_BUILD_TYPE ||
        setup.seal_acceleration != LAMINATE_SEAL_ACCELERATION ||
        std::string_view(LAMINATE_BASE_CHECKPOINT_GIT_DIRTY) != "false") {
        throw std::invalid_argument(
            "the current executable does not match setup.bin's clean "
            "revision and build configuration");
    }
}

// Reuse only the fully published artifacts from the known profile-decoder
// failure. The exclusive source lock remains held until the new setup ends.
struct ProcessSetupRecovery {
    RunLifecycleLock lifecycle;
    ProcessSetupRecord stored;
    std::vector<std::uint8_t> setup_bytes;
    std::vector<std::uint8_t> server_bytes;
    std::vector<std::uint8_t> client_context_bytes;
    std::vector<std::uint8_t> client_static_bytes;
    std::shared_ptr<const gates::GateTableProverKey> gate_key;
};

ProcessSetupRecovery load_process_setup_recovery(
    const ProcessCommand &command) {
    require(!command.recover_from.empty() &&
                command.recover_from.is_absolute() &&
                command.recover_from != command.recover_from.root_path(),
            "setup recovery requires an absolute source run directory");
    const auto require_owned_path = [](const std::filesystem::path &path,
                                       bool directory) {
        struct stat metadata {};
        if (::lstat(path.c_str(), &metadata) != 0 ||
            (directory ? !S_ISDIR(metadata.st_mode)
                       : !S_ISREG(metadata.st_mode)) ||
            metadata.st_uid != ::geteuid() ||
            (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            throw std::runtime_error(
                "setup recovery requires an owner-controlled real "
                "artifact: " + path.string());
        }
    };
    require_owned_path(command.recover_from, true);
    const std::filesystem::path source =
        std::filesystem::canonical(command.recover_from);
    const std::filesystem::path destination =
        std::filesystem::weakly_canonical(command.run_directory);
    const auto contains_path = [](const std::filesystem::path &parent,
                                  const std::filesystem::path &child) {
        return std::mismatch(parent.begin(), parent.end(), child.begin(),
                             child.end()).first == parent.end();
    };
    require(!contains_path(source, destination) &&
                !contains_path(destination, source),
            "setup recovery source and destination must be separate runs");
    for (const char *relative :
         {"shared", "shared/transcript", "client", "client/preprocessing",
          "client/work", "server", "server/preprocessing", "server/work"}) {
        require_owned_path(source / relative, true);
    }
    // RunLifecycleLock normally creates a missing lock. Reject that case
    // first so opening a failed source never adds an artifact to it.
    require_owned_path(source / "shared/lifecycle.lock", false);
    RunLifecycleLock lifecycle(source, RunLifecycleLockMode::Exclusive);

    const auto missing = [](const std::filesystem::path &path) {
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        return (error == std::errc::no_such_file_or_directory) ||
               (!error && status.type() ==
                              std::filesystem::file_type::not_found);
    };
    require(missing(source / "shared/setup-result.txt") &&
                missing(source / "shared/setup-result.txt.partial"),
            "setup recovery requires a source without a setup result");
    for (const char *role : {"client", "server"}) {
        for (const auto &entry :
             std::filesystem::directory_iterator(source / role)) {
            const auto name = entry.path().filename();
            require(name == "preprocessing" || name == "work",
                    "setup recovery source contains online role artifacts");
        }
        require(std::filesystem::is_empty(source / role / "work"),
                "setup recovery source contains online work artifacts");
    }
    require(std::filesystem::is_empty(source / "shared/transcript"),
            "setup recovery source contains online transcript artifacts");

    const auto read_text = [&](const char *relative,
                               std::uint64_t maximum_bytes) {
        const auto path = source / relative;
        require_owned_path(path, false);
        const auto bytes = read_bounded_file(path, maximum_bytes);
        return std::string(bytes.begin(), bytes.end());
    };
    require(read_text("shared/setup-failure.txt", 4096) ==
                "FAILED: setup profile exceeds its decode limit\n" &&
                read_text("shared/setup-process-exit.txt", 4096) ==
                    "process.exit_status=1\n",
            "setup recovery only accepts the completed profile decode "
            "failure");
    const std::string activity =
        read_text("shared/setup-activity.jsonl", std::uint64_t{4} << 20U);
    require(activity.find(
                "\"event\":\"stage\",\"stage\":\"verifying_preprocessing\"") !=
                std::string::npos &&
                activity.find(
                    "\"event\":\"stop\",\"stage\":\"exception\"") !=
                    std::string::npos,
            "setup recovery source did not reach preprocessing verification");

    require_owned_path(source / "shared/setup.bin", false);
    std::vector<std::uint8_t> setup_bytes = read_bounded_file(
        source / "shared/setup.bin", kProcessMaximumSetupBytes);
    ProcessSetupRecord stored = decode_process_setup(setup_bytes);
    require(stored.variant == command.variant &&
                stored.profile == command.profile,
            "setup recovery source variant/profile does not match");
    // Limit recovery to reviewed source revisions. Passing this allowlist
    // does not bypass the GateMLE format, statement, schedule, or resource
    // checks: successful metadata decoding alone cannot establish compatibility.
    constexpr std::array<std::string_view, 3> compatible_revisions{
        "075837687d0740eb9b0fcdea865fc28ad8f7e819",
        "8396bc6dcf50f2bcf0e39e22b584bec57daac117",
        "2254094404440796c0a4aff1a449fbc9dc6cc9b4"};
    const bool compatible_revision =
        std::find(compatible_revisions.begin(), compatible_revisions.end(),
                  stored.git_commit) != compatible_revisions.end() ||
        (stored.git_commit == LAMINATE_BASE_CHECKPOINT_GIT_COMMIT &&
         std::string_view(LAMINATE_BASE_CHECKPOINT_GIT_DIRTY) == "false");
    require(compatible_revision && stored.build_type == "Release" &&
                stored.build_type == LAMINATE_BUILD_TYPE &&
                stored.seal_acceleration == LAMINATE_SEAL_ACCELERATION,
            "setup recovery source has an unsupported revision or build");
    const std::string expected_binding =
        "format=laminate-benchmark-run-v1\nrun.variant=" + stored.variant +
        "\nrun.profile=" + stored.profile + "\nrun.id=" +
        digest_hex(stored.run_id) + "\n";
    require(read_text("shared/run-binding.txt", 4096) == expected_binding,
            "setup recovery source has a noncanonical run binding");

    const auto selected = process_profile(command.profile);
    const Options options = process_options(
        command, selected, require_bound_host_budget(stored));
    const std::uint64_t client_bytes =
        require_process_client_preprocessing_bound(options, stored);
    const std::uint64_t server_limit = diagnostic_scaled_bytes(
        options.diagnostic.slots, std::uint64_t{2} << 30U,
        std::uint64_t{1} << 28U,
        "diagnostic server preprocessing upper");
    require(stored.server_bytes > 0 &&
                stored.server_bytes <= server_limit &&
                stored.client_context_bytes > 0 &&
                stored.client_static_bytes > 0 &&
                client_bytes <= base_client_preprocessing_bytes_upper(
                                    options.diagnostic.slots),
            "setup recovery preprocessing sizes exceed profile bounds");
    const auto load_artifact = [&](const char *relative,
                                   std::uint64_t expected_bytes,
                                   const Digest &expected_digest) {
        const auto path = source / relative;
        require_owned_path(path, false);
        std::vector<std::uint8_t> bytes =
            read_bounded_file(path, expected_bytes);
        require(bytes.size() == expected_bytes &&
                    sha256(bytes) == expected_digest,
                "setup recovery artifact size or digest differs from "
                "setup.bin");
        return bytes;
    };
    std::vector<std::uint8_t> server_bytes = load_artifact(
        "server/preprocessing/server.bin", stored.server_bytes,
        stored.server_digest);
    std::vector<std::uint8_t> client_context_bytes = load_artifact(
        "client/preprocessing/client.bin", stored.client_context_bytes,
        stored.client_context_digest);
    std::vector<std::uint8_t> client_static_bytes = load_artifact(
        "client/preprocessing/client-static.bin", stored.client_static_bytes,
        stored.client_static_digest);
    require(stored.gate_mle_verifier.has_value(), "recovery lacks GateMLE verifier state");
    auto gate_key = std::make_shared<gates::GateTableProverKey>(
        gates::reopen_gate_table_prover_key(*stored.gate_mle_verifier,
            source / "server/preprocessing/gate-mle",
            gates::GateTableBuildOptions{.wide_max_disk_bytes = options.diagnostic.max_live_disk_bytes}));
    return ProcessSetupRecovery{
        std::move(lifecycle), std::move(stored), std::move(setup_bytes),
        std::move(server_bytes), std::move(client_context_bytes),
        std::move(client_static_bytes), std::move(gate_key)};
}

DiagnosticPreflight restore_setup_recovery_preflight(
    const ProcessSetupRecovery &recovery, const ProcessProfile &selected,
    const Options &options, const RunProfile &profile,
    const LayeredCircuit &circuit) {
    auto schedule = restore_process_schedule(
        recovery.stored, profile, circuit,
        selected.proof_ingress_rns_limbs);
    auto public_setup = restore_process_public_setup(
        recovery.stored, profile.payload, circuit, schedule);
    auto restored = finish_diagnostic_preflight(
        options, profile, circuit, std::move(schedule),
        std::move(public_setup));
    require(restored.public_setup.payload_digest ==
                recovery.stored.payload_digest &&
                restored.public_setup.layered_digest ==
                    recovery.stored.layered_digest &&
                restored.public_setup.circuit_digest ==
                    recovery.stored.circuit_digest &&
                restored.schedule().fresh_modulus_product_bits ==
                    recovery.stored.fresh_modulus_product_bits &&
                restored.replay_budgets == recovery.stored.replay_budgets &&
                base_replay_plan_digest(restored.replay_plan) ==
                    recovery.stored.replay_plan_digest &&
                restored.client_peak_resident_bytes_upper ==
                    recovery.stored.client_peak_resident_bytes &&
                restored.wire_limits == recovery.stored.client_wire_limits,
            "recovery source differs from the current workload or resource plan");
    require(recovery.stored.server_bytes <=
                restored.server_preprocessing_bytes_upper &&
                require_process_client_preprocessing_bound(
                    options, recovery.stored) <=
                    restored.client_preprocessing_bytes_upper,
            "recovery preprocessing exceeds the current profile bounds");
    return restored;
}

SealBackend::Contexts restore_setup_recovery_contexts(
    const ProcessSetupRecovery &recovery, const SealParameters &parameters) {
    SealBackend::Contexts restored = SealBackend::deserialize_context_bundles(
        recovery.server_bytes, recovery.client_context_bytes);
    require(restored.eval.parameters == parameters &&
                restored.client.parameters == parameters,
            "recovery SEAL parameters differ from the selected profile");
    return restored;
}

int run_process_setup(const ProcessCommand &command, int argc,
                      char **argv, bool &created_run) {
    const auto execution = setup_execution(true);
    Stopwatch total_stopwatch;
    const std::int64_t started = unix_milliseconds();
    require_gcp_benchmark_build();
    std::optional<ProcessSetupRecovery> recovery;
    if (!command.recover_from.empty()) {
        recovery.emplace(load_process_setup_recovery(command));
    }
    create_process_run_tree(command.run_directory);
    created_run = true;
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(
        command.run_directory / "shared" / "setup-activity.jsonl",
        "setup");
    const auto transition = [&](std::string_view stage,
                                std::string_view description) {
        activity.transition(stage);
        std::cout << "SETUP: " << description << std::endl;
    };
    const Digest process_run_id = random_digest();
    publish_process_run_binding(command, digest_hex(process_run_id));
    const ProcessProfile selected = process_profile(command.profile);

    // Step 1: Freeze the planner budget before constructing the payload or
    // cryptographic preprocessing. Profile geometry remains fixed; only
    // checkpoint placement adapts to this recorded host envelope.
    transition("deriving_host_resource_budget",
               "deriving disk and RAM budgets from this host");
    std::error_code error;
    const std::filesystem::space_info space =
        std::filesystem::space(command.run_directory, error);
    require(!error &&
                space.available <=
                    std::numeric_limits<std::uint64_t>::max(),
            "failed to inspect benchmark filesystem capacity");
    const SystemInfo host = system_info();
    require(host.ram_bytes != 0,
            "failed to inspect benchmark physical RAM");
    // Recovery preserves the admitted plan's envelope; actual free capacity
    // is still checked below before copying any preprocessing into this run.
    const HostResourceBudget host_budget = recovery
        ? require_bound_host_budget(recovery->stored)
        : derive_host_resource_budget(
              static_cast<std::uint64_t>(space.available), host.ram_bytes);
    std::cout
        << "SETUP: host-derived planner budget reserves "
        << kBenchmarkFreeDiskReserveBytes << " disk bytes and "
        << kBenchmarkOperatingSystemRamReserveBytes << " OS RAM bytes plus "
        << kBenchmarkPageCacheRamReserveBytes << " page-cache bytes; "
        << host_budget.max_live_disk_bytes
        << " gross live-disk bytes and "
        << host_budget.max_resident_ram_bytes
        << " resident bytes remain usable" << std::endl;
    const Options options =
        process_options(command, selected, host_budget);
    std::cout
        << "SETUP: reserving "
        << options.diagnostic.client_private_persistent_disk_bytes
        << " bytes for persistent client preprocessing leaves "
        << options.diagnostic.max_live_disk_bytes
        << " bytes for the Base server plan" << std::endl;

    std::cout << "SETUP: GateMLE preprocessing uses "
              << execution.worker_threads << " worker(s)" << std::endl;
    transition("compiling_circuit",
               "compiling the circuit before schedule and capacity checks");
    Stopwatch preflight_stopwatch;
    RunProfile profile = make_run_profile(options, false);
    LayeredCircuit circuit = compile(profile.payload);
    const DiagnosticPreflight preflight = [&] {
        if (!recovery) {
            return preflight_diagnostic(
                options, profile, circuit,
                selected.proof_ingress_rns_limbs, execution.worker_threads,
                transition);
        }
        transition("recovery_preflight",
                   "validating saved schedule, GateMLE roots, and resource plan");
        return restore_setup_recovery_preflight(
            *recovery, selected, options, profile, circuit);
    }();
    if (recovery) {
        // Cross-filesystem export may copy the whole cache. Admit its disk
        // demand before publishing any recovered preprocessing files.
        (void)require_diagnostic_host(
            options, preflight, DiagnosticHostAdmissionPoint::SetupStart);
        transition("persisting_gate_mle", "retaining compatible saved GateMLE opening state");
        gates::export_gate_table_prover_key(*recovery->gate_key,
            command.run_directory / "server/preprocessing/gate-mle");
    }
    const auto persisted_gate_bytes =
        preflight.capacity_components.gate_mle_preprocessing.local_disk_bytes;
    const auto required_disk_after_gate = diagnostic_required_available_disk(
        options, preflight, DiagnosticHostAdmissionPoint::SetupStart,
        persisted_gate_bytes);
    const auto available_disk_after_gate = require_diagnostic_host(
        options, preflight, DiagnosticHostAdmissionPoint::SetupStart,
        persisted_gate_bytes);
    const Timing preflight_timing = preflight_stopwatch.stop();
    std::cout << "SETUP: fixed-schedule preflight complete in "
              << std::fixed << std::setprecision(3)
              << preflight_timing.wall_ms / 1000.0 << " seconds"
              << std::endl;
    std::cout << "SETUP: disk admission predicts "
              << preflight.capacity_admission.max_live_local_disk_bytes
              << " live server bytes; after retaining GateMLE preprocessing, setup requires "
              << required_disk_after_gate
              << " available bytes and the filesystem reports "
              << available_disk_after_gate << std::endl;
    std::cout << "SETUP: checkpoint plan retains "
              << preflight.replay_plan.selected.checkpoint_layers.size()
              << " layers ("
              << preflight.replay_plan.selected.checkpoint_bytes
              << " bytes), peaks at "
              << preflight.replay_plan.selected.peak_live_scratch_bytes
              << " replay bytes, and uses " << std::fixed
              << std::setprecision(4)
              << static_cast<double>(
                     preflight.replay_plan.selected.cumulative_work_units) /
                     static_cast<double>(
                         preflight.replay_plan.selected.initial_forward_work_units)
              << "x cumulative payload work" << std::defaultfloat
              << std::setprecision(6) << std::endl;
    std::cout << "SETUP: payload replay work = "
              << preflight.replay_plan.selected.replay_work_units
              << "; remaining admitted disk headroom = "
              << options.diagnostic.max_live_disk_bytes -
                     preflight.replay_plan.selected.peak_live_scratch_bytes
              << " bytes" << std::endl;

    transition(recovery ? "restoring_seal_keys" : "seal_key_generation",
               recovery ? "restoring and verifying saved SEAL role keys"
                   : profile.seal_parameters.generate_galois_keys
                       ? "generating SEAL public, relinearization, and Galois keys"
                       : "generating SEAL public and relinearization keys");
    auto generated = timed([&] {
        if (!recovery) return SealBackend::create(profile.seal_parameters);
        return restore_setup_recovery_contexts(*recovery, profile.seal_parameters);
    });
    SealBackend::Contexts contexts = std::move(generated.first);
    const Timing key_generation_timing = generated.second;
    std::vector<std::uint64_t> actual_moduli =
        SealBackend::coefficient_moduli(contexts.eval);
    require(actual_moduli.size() ==
                profile.seal_parameters.exact_data_primes.size() + 1U,
            "SEAL key context does not contain one special prime");
    actual_moduli.pop_back();
    require(actual_moduli == profile.seal_parameters.exact_data_primes,
            "SEAL coefficient moduli differ from the selected profile");

    transition("client_static_preprocessing",
               "certifying and encoding reusable client verifier state");
    Stopwatch client_static_stopwatch;
    protocol::CertifiedBaseClientSetup<SealBackend> certified_client =
        protocol::certify_base_client_setup<SealBackend>(
            std::move(profile.payload), std::move(circuit),
            make_client_setup<SealBackend>(
                preflight.public_setup, std::move(contexts.client)));
    require_process_client_profile_geometry(selected, certified_client);
    std::vector<std::uint8_t> client_static_bytes =
        protocol::encode_base_client_static_setup(certified_client);
    if (recovery) {
        require(client_static_bytes == recovery->client_static_bytes,
                "saved client verifier state differs from current certification");
    }
    const Timing client_static_timing = client_static_stopwatch.stop();

    transition("persisting_preprocessing",
               "serializing and writing role-separated preprocessing");
    ProcessSetupRecord stored;
    stored.variant = command.variant;
    stored.profile = command.profile;
    stored.git_commit = LAMINATE_BASE_CHECKPOINT_GIT_COMMIT;
    stored.build_type = LAMINATE_BUILD_TYPE;
    stored.seal_acceleration = LAMINATE_SEAL_ACCELERATION;
    stored.run_id = process_run_id;
    stored.public_setup_digest = setup_digest(preflight.public_setup);
    stored.payload_digest = preflight.public_setup.payload_digest;
    stored.layered_digest = preflight.public_setup.layered_digest;
    stored.circuit_digest = preflight.public_setup.circuit_digest;
    require(preflight.public_setup.honest_payload_noise_schedule_digest
                .has_value(),
            "fixed-policy setup omitted its schedule binding");
    stored.schedule_digest =
        *preflight.public_setup.honest_payload_noise_schedule_digest;
    stored.gate_mle_verifier = preflight.public_setup.outsourced_gate_mle;
    stored.proof_schedule_policy =
        std::string(kUniformBaseProofIngressPolicyV1);
    stored.proof_ingress_rns_limbs =
        selected.proof_ingress_rns_limbs;
    stored.fresh_modulus_product_bits =
        preflight.schedule().fresh_modulus_product_bits;
    stored.host_budget = host_budget;
    stored.replay_budgets = preflight.replay_budgets;
    stored.replay_plan_digest =
        base_replay_plan_digest(preflight.replay_plan);
    stored.client_peak_resident_bytes =
        preflight.client_peak_resident_bytes_upper;
    stored.client_wire_limits = preflight.wire_limits;

    Stopwatch persist_stopwatch;
    std::vector<std::uint8_t> server_bytes =
        SealBackend::serialize_evaluation_context_bundle(contexts.eval);
    std::vector<std::uint8_t> client_context_bytes =
        SealBackend::serialize_client_context_bundle(
            certified_client.context());
    if (recovery) {
        require(server_bytes == recovery->server_bytes &&
                    client_context_bytes == recovery->client_context_bytes,
                "recovered SEAL role bundles changed during restoration");
    }
    stored.server_bytes = server_bytes.size();
    stored.server_digest = sha256(server_bytes);
    stored.client_context_bytes = client_context_bytes.size();
    stored.client_context_digest = sha256(client_context_bytes);
    stored.client_static_bytes = client_static_bytes.size();
    stored.client_static_digest = sha256(client_static_bytes);
    const std::uint64_t client_preprocessing_bytes =
        require_process_client_preprocessing_bound(options, stored);
    require(stored.server_bytes <=
                preflight.server_preprocessing_bytes_upper &&
                client_preprocessing_bytes <=
                    preflight.client_preprocessing_bytes_upper,
            "serialized preprocessing exceeds the preflight disk "
            "allowance");
    const std::vector<std::uint8_t> setup_bytes =
        encode_process_setup(stored);
    const std::uint64_t persisted_preprocessing_bytes = checked_add_u64(
        checked_add_u64(stored.server_bytes, client_preprocessing_bytes,
                        "persisted role preprocessing"),
        checked_add_u64(setup_bytes.size(),
                        recovery ? recovery->setup_bytes.size() : 0,
                        "persisted setup and recovery evidence"),
        "persisted setup preprocessing");
    require(persisted_preprocessing_bytes <=
                preflight.all_preprocessing_bytes_upper,
            "persisted preprocessing exceeds the aggregate preflight "
            "disk allowance");
    publish_private_file(
        command.run_directory / "server" / "preprocessing" /
            "server.bin",
        server_bytes);
    publish_private_file(
        command.run_directory / "client" / "preprocessing" /
            "client.bin",
        client_context_bytes);
    publish_private_file(
        command.run_directory / "client" / "preprocessing" /
            "client-static.bin",
        client_static_bytes);
    publish_private_file(
        command.run_directory / "shared" / "setup.bin", setup_bytes);
    const Timing persist_timing = persist_stopwatch.stop();

    // Reopen every persisted file before publishing PASS. Each role later
    // sees only its own preprocessing plus the common immutable setup record.
    transition("verifying_preprocessing",
               "reopening and verifying persisted preprocessing");
    Stopwatch verification_stopwatch;
    const ProcessSetupRecord reopened = load_process_setup(command);
    (void)require_bound_host_budget(reopened);
    require(encode_process_setup(reopened) == setup_bytes &&
                reopened.server_digest == stored.server_digest &&
                reopened.client_context_digest ==
                    stored.client_context_digest &&
                reopened.client_static_digest ==
                    stored.client_static_digest &&
                reopened.replay_budgets == preflight.replay_budgets &&
                reopened.replay_plan_digest ==
                    base_replay_plan_digest(preflight.replay_plan),
            "setup.bin changed while it was published");
    {
        std::vector<std::uint8_t> reopened_server = read_bounded_file(
            command.run_directory / "server" / "preprocessing" /
                "server.bin",
            reopened.server_bytes);
        std::vector<std::uint8_t> reopened_client = read_bounded_file(
            command.run_directory / "client" / "preprocessing" /
                "client.bin",
            reopened.client_context_bytes);
        std::vector<std::uint8_t> reopened_client_static =
            read_bounded_file(
                command.run_directory / "client" / "preprocessing" /
                    "client-static.bin",
                reopened.client_static_bytes);
        require(reopened_server.size() == reopened.server_bytes &&
                    sha256(reopened_server) == reopened.server_digest &&
                    reopened_client.size() ==
                        reopened.client_context_bytes &&
                    sha256(reopened_client) ==
                        reopened.client_context_digest &&
                    reopened_client_static.size() ==
                        reopened.client_static_bytes &&
                    sha256(reopened_client_static) ==
                        reopened.client_static_digest,
                "role preprocessing failed its setup digest check");
        std::vector<std::uint8_t>().swap(reopened_server);
        protocol::AuthenticatedBaseClientStaticSetup reopened_static =
            protocol::decode_authenticated_base_client_static_setup(
                reopened_client_static, reopened.client_static_digest,
                reopened.public_setup_digest, reopened.circuit_digest,
                process_client_static_decode_limits(
                    selected, options, reopened));
        std::vector<std::uint8_t>().swap(reopened_client_static);
        SealBackend::ClientContext reopened_context =
            SealBackend::deserialize_client_context_bundle(
                reopened_client);
        std::vector<std::uint8_t>().swap(reopened_client);
        require(reopened_context.parameters == profile.seal_parameters,
                "reopened client context differs from the selected profile");
        PublicSetup reopened_public_setup =
            restore_process_client_public_setup(
                reopened, reopened_static.payload_shape(),
                reopened_static.layer_count(),
                selected.proof_ingress_rns_limbs);
        const protocol::CertifiedBaseClientSetup<SealBackend>
            reopened_certified =
                protocol::restore_base_client_setup<SealBackend>(
                    std::move(reopened_static),
                    make_client_setup<SealBackend>(
                        std::move(reopened_public_setup),
                        std::move(reopened_context)));
        require_process_client_profile_geometry(
            selected, reopened_certified);
    }
    const Timing verification_timing = verification_stopwatch.stop();

    transition("publishing_result", "publishing the setup result");
    const Timing total_timing = total_stopwatch.stop();
    const std::int64_t finished = unix_milliseconds();
    CompletedResultReport report(
        command.run_directory / "shared" / "setup-result.txt");
    const Record record(report.mirror());
    record.text("format", "laminate-benchmark-setup-v1");
    emit_process_identity(record, command, stored);
    record.text("setup.mode", recovery ? "recovered-preprocessing" : "fresh");
    record.text("timing.setup.scope", recovery
        ? "recovery-only-excludes-original-preprocessing"
        : "complete-fresh-setup");
    if (recovery) {
        record.text("recovery.source_run_directory",
                    std::filesystem::canonical(command.recover_from).string());
        record.text("recovery.source_run_id", digest_hex(recovery->stored.run_id));
        record.text("recovery.source_git_commit", recovery->stored.git_commit);
        record.text("recovery.source_setup_sha256", digest_hex(sha256(recovery->setup_bytes)));
        record.integer("storage.recovery_source_setup_bytes", recovery->setup_bytes.size());
        record.text("recovery.source_failure", "setup profile exceeds its decode limit");
        // Preserve the source record as evidence without changing its run
        // identity, build provenance, or any file in the failed source run.
        publish_private_file(command.run_directory / "shared" /
                                 "recovery-source-setup.bin",
                             recovery->setup_bytes);
    }
    record.integer("timing.setup.started_unix_ms", started);
    record.integer("timing.setup.finished_unix_ms", finished);
    record.integer("parameters.slots",
                   certified_client.circuit().shape.slot_count);
    record.integer("parameters.payload_multiplicative_depth",
                   selected.multiplicative_depth);
    const BenchmarkPayloadProfile payload_profile =
        benchmark_payload_profile(command.profile);
    record.text("parameters.payload_workload",
                std::string(workload_name(payload_profile.workload_kind)));
    record.integer("parameters.payload_width",
                   selected.middle_width);
    record.integer("parameters.payload_inputs",
                   certified_client.payload().input_count);
    record.integer("parameters.payload_outputs",
                   certified_client.payload().outputs.size());
    record.integer("parameters.payload_operations",
                   certified_client.payload().gates.size());
    record.integer("parameters.payload_add_gates",
                   payload_profile.add_gates);
    record.integer("parameters.payload_add_plain_gates",
                   payload_profile.add_plain_gates);
    record.integer("parameters.payload_mul_gates",
                   payload_profile.mul_gates);
    record.integer("parameters.payload_mul_plain_gates",
                   payload_profile.mul_plain_gates);
    record.integer("parameters.payload_rotate_gates",
                   payload_profile.rotate_gates);
    record.integer("parameters.compiled_layers",
                   certified_client.circuit().layers.size());
    record.integer("parameters.initial_ciphertext_modulus_bits",
                   preflight.schedule().fresh_modulus_product_bits);
    record.integer("parameters.key_modulus_product_bits",
                   SealBackend::key_modulus_bits(contexts.eval));
    record.integer("parameters.plaintext_modulus", kBaseFieldOrder);
    record.text("parameters.security",
                "SEAL sec_level_type::none (comparison profile)");
    record.text("parameters.initial_ciphertext_modulus_primes",
                decimal_list(profile.seal_parameters.exact_data_primes));
    record.integer("parameters.fresh_rns_limbs",
                   profile.seal_parameters.fresh_rns_limbs);
    record.text("parameters.galois_keys",
                profile.seal_parameters.generate_galois_keys
                    ? "generated"
                    : "omitted-no-payload-rotation-gates");
    record.text("parameters.base_proof_schedule_policy",
                stored.proof_schedule_policy);
    record.text("parameters.base_payload_noise_model",
                std::string(preflight.schedule().payload_noise_model));
    record.integer("parameters.base_proof_ingress_rns_limbs",
                   stored.proof_ingress_rns_limbs);
    record.text("parameters.gate_mle_profile",
                "wide-local-adjoint-foldable");
    const gates::GateTableVerifierKey &gate_mle =
        *preflight.public_setup.outsourced_gate_mle;
    record.integer("parameters.gate_mle_tables",
                   gate_mle.tables.size());
    record.integer("parameters.gate_mle_basefold_log_rate",
                   gate_mle.basefold_parameters.log_rate);
    record.integer("parameters.gate_mle_basefold_queries",
                   laminate::bench::gate_mle_query_count(gate_mle));
    record.integer("security.basefold.target_bits", kBaseFoldIntegrityTargetBits);
    record.text("security.basefold.bound_model", "unique-decoding-rbr");
    record.integer("security.basefold.gate_rbr_bits",
                   gate_mle_basefold_soundness_bits(gate_mle));
    record.text(
        "parameters.gate_mle_server_state",
        "persisted-opening-state-reopened-at-server-startup");
    record.text("parameters.gate_mle_wire_bound",
                "setup-shaped-opening-bound");
    record.text("parameters.base_proof_noise_assessment",
                "offline-calibration-only-not-run-during-setup");
    record.text("public_setup.digest",
                digest_hex(stored.public_setup_digest));
    emit_timing_pair(record, "timing.setup.preflight", preflight_timing);
    emit_timing_pair(record, recovery ? "timing.setup.key_restoration"
                                     : "timing.setup.key_generation",
                     key_generation_timing);
    emit_timing_pair(record, "timing.setup.client_static_preprocessing",
                     client_static_timing);
    emit_timing_pair(record, "timing.setup.persist", persist_timing);
    emit_timing_pair(record, "timing.setup.verify_persisted",
                     verification_timing);
    emit_timing_pair(record, "timing.setup.total", total_timing);
    record.integer("storage.setup_bytes", setup_bytes.size());
    record.integer("storage.server_preprocessing_bytes",
                   stored.server_bytes);
    record.integer("storage.client_preprocessing_bytes",
                   client_preprocessing_bytes);
    record.integer("storage.client_context_bytes",
                   stored.client_context_bytes);
    record.integer("storage.client_static_verifier_bytes",
                   stored.client_static_bytes);
    record.integer("storage.predicted_peak_live_server_bytes",
                   preflight.capacity_admission.max_live_local_disk_bytes);
    record.text(
        "storage.payload_replay_plan.selection_objective",
        preflight.replay_budgets.selection_objective ==
                PayloadCheckpointSelectionObjective::MinimumReplayWork
            ? "minimum-replay-work"
            : "minimum-storage");
    record.integer(
        "storage.payload_replay_plan.selected_peak_live_bytes",
        preflight.replay_plan.selected.peak_live_scratch_bytes);
    record.integer(
        "memory.payload_replay_plan.selected_peak_resident_bytes",
        preflight.replay_plan.selected.peak_resident_bytes);
    record.integer(
        "memory.payload_replay_plan.dense_multiplication_alias_cache_peak_resident_bytes",
        preflight.replay_plan.selected
            .dense_multiplication_alias_cache_peak_resident_bytes);
    record.integer(
        "storage.payload_replay_plan.selected_checkpoint_count",
        preflight.replay_plan.selected.checkpoint_layers.size());
    record.text(
        "storage.payload_replay_plan.selected_checkpoint_layers",
        index_list(preflight.replay_plan.selected.checkpoint_layers));
    record.integer(
        "storage.payload_replay_plan.selected_checkpoint_bytes",
        preflight.replay_plan.selected.checkpoint_bytes);
    record.text("storage.payload_replay_plan.digest",
                digest_hex(stored.replay_plan_digest));
    record.integer(
        "work.payload_replay_plan.initial_forward_units",
        preflight.replay_plan.selected.initial_forward_work_units);
    record.integer(
        "work.payload_replay_plan.repeated_units",
        preflight.replay_plan.selected.replay_work_units);
    record.integer(
        "work.payload_replay_plan.cumulative_units",
        preflight.replay_plan.selected.cumulative_work_units);
    record.real(
        "work.payload_replay_plan.cumulative_factor",
        static_cast<double>(
            preflight.replay_plan.selected.cumulative_work_units) /
            static_cast<double>(
                preflight.replay_plan.selected.initial_forward_work_units));
    record.integer(
        "memory.gate_mle_retained_prover_key_upper_bytes",
        preflight.capacity_components.gate_mle_preprocessing
            .resident_ram_bytes);
    record.integer(
        "memory.gate_mle_opening_workspace_upper_bytes",
        preflight.capacity_components.gate_mle_opening_workspace
            .resident_ram_bytes);
    record.text(
        "storage.predicted_peak_live_server_phase",
        diagnostic_capacity_phase_name(
            preflight.capacity_admission
                .peak_live_local_disk_phase()
                .phase));
    record.integer("storage.configured_live_server_cap_bytes",
                   preflight.capacity_caps.max_live_local_disk_bytes);
    record.integer(
        "storage.predicted_multiplication_build_peak_bytes",
        preflight.capacity_components.multiplication_build_scratch
            .local_disk_bytes);
    record.integer(
        "storage.predicted_multiplication_artifact_bytes",
        preflight.capacity_components.multiplication_artifact
            .local_disk_bytes);
    record.integer("storage.required_setup_start_available_bytes",
                   preflight.setup_start_available_disk_bytes);
    record.integer("storage.required_server_start_available_bytes",
                   preflight.server_start_available_disk_bytes);
    record.integer("storage.observed_setup_start_available_bytes",
                   static_cast<std::uint64_t>(space.available));
    record.integer("storage.required_setup_after_gate_available_bytes",
                   required_disk_after_gate);
    record.integer("storage.observed_setup_after_gate_available_bytes",
                   available_disk_after_gate);
    record.integer("storage.already_present_gate_preprocessing_upper_bytes",
                   persisted_gate_bytes);
    record.integer("storage.required_free_space_reserve_bytes",
                   options.diagnostic.min_free_disk_bytes);
    record.integer("storage.predicted_peak_resident_server_bytes",
                   preflight.capacity_admission.max_resident_ram_bytes);
    record.integer(
        "memory.multiplication_sort_buffer_limit_bytes",
        preflight.multiplication_sort_buffer_payload_bytes);
    record.integer("memory.client.admitted_peak_resident_bytes",
                   preflight.client_peak_resident_bytes_upper);
    record.integer("memory.concurrent.admitted_peak_resident_bytes",
                   checked_add_u64(
                       preflight.capacity_admission.max_resident_ram_bytes,
                       preflight.client_peak_resident_bytes_upper,
                       "reported Base concurrent resident peak"));
    record.integer(
        "storage.host_budget.observed_available_disk_bytes",
        host_budget.observed_available_disk_bytes);
    record.integer("storage.host_budget.free_reserve_bytes",
                   kBenchmarkFreeDiskReserveBytes);
    record.integer("storage.host_budget.max_live_disk_bytes",
                   host_budget.max_live_disk_bytes);
    record.integer(
        "storage.host_budget.client_private_persistence_reserve_bytes",
        options.diagnostic.client_private_persistent_disk_bytes);
    record.integer("storage.host_budget.server_live_disk_cap_bytes",
                   options.diagnostic.max_live_disk_bytes);
    record.integer("memory.host_budget.observed_physical_ram_bytes",
                   host_budget.observed_physical_ram_bytes);
    record.integer("memory.host_budget.safety_reserve_bytes",
                   kBenchmarkHostRamSafetyReserveBytes);
    record.integer("memory.host_budget.operating_system_reserve_bytes",
                   kBenchmarkOperatingSystemRamReserveBytes);
    record.integer("memory.host_budget.page_cache_reserve_bytes",
                   kBenchmarkPageCacheRamReserveBytes);
    record.integer("memory.payload_storage.transfer_buffer_count", 3);
    record.integer("memory.payload_storage.transfer_buffer_bytes_each",
                   kFileTraceStoreTransferBufferBytes);
    record.integer("memory.payload_storage.transfer_buffer_reserve_bytes",
                   kPayloadStorageTransferResidentBytes);
    record.integer("memory.payload_storage.writeback_window_bytes", 0);
    record.text("storage.payload_storage.ephemeral_writeback_policy",
                "linux-submit-only-with-buffered-portable-fallback");
    record.integer(
        "storage.payload_storage.maximum_writeback_submission_bytes",
        kFileTraceStoreWritebackSubmissionBytes);
    record.integer("memory.payload_storage.sequential_reader_count", 2);
    record.integer("memory.payload_storage.prefetch_window_bytes_each",
                   kFileTraceStorePrefetchWindowBytes);
    record.integer("memory.payload_storage.prefetch_page_cache_budget_bytes",
                   2U * kFileTraceStorePrefetchWindowBytes);
    record.integer("storage.payload_storage.maximum_prefetch_request_bytes",
                   kFileTraceStorePrefetchRequestBytes);
    record.integer("memory.host_budget.gross_resident_budget_bytes",
                   host_budget.max_resident_ram_bytes);
    record.integer("memory.host_budget.client_peak_reserve_bytes",
                   preflight.client_peak_resident_bytes_upper);
    record.integer("memory.host_budget.server_resident_cap_bytes",
                   preflight.capacity_caps.max_resident_ram_bytes);
    record.integer(
        "storage.payload_replay_plan.remaining_headroom_bytes",
        options.diagnostic.max_live_disk_bytes -
            preflight.replay_plan.selected.peak_live_scratch_bytes);
    const SystemInfo final_setup_system = system_info();
    require(final_setup_system.peak_rss_bytes <=
                host_budget.max_resident_ram_bytes,
            "Base setup peak RSS consumes the fixed host RAM reserve");
    record.integer("memory.setup.peak_rss_bytes",
                   final_setup_system.peak_rss_bytes);
    record.text("environment.command", exact_command(argc, argv));
    record.text("setup.result", "PASS");
    report.publish();
    activity.mark_complete();
    std::cout << "\nSETUP PASS\n"
              << "Client preprocessing: "
              << (command.run_directory / "client" / "preprocessing" /
                  "client.bin")
              << "\nClient static verifier preprocessing: "
              << (command.run_directory / "client" / "preprocessing" /
                  "client-static.bin")
              << "\nServer preprocessing: "
              << (command.run_directory / "server" / "preprocessing" /
                  "server.bin")
              << "\nStart the client, then the server.\n";
    return 0;
}

bool result_contains(const std::filesystem::path &path,
                     std::string_view expected_line) {
    std::ifstream input(path);
    if (!input) {
        return false;
    }
    for (std::string line; std::getline(input, line);) {
        if (line == expected_line) {
            return true;
        }
    }
    return false;
}

bool regular_file_exists(const std::filesystem::path &path) {
    std::error_code error;
    return std::filesystem::is_regular_file(path, error) && !error;
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
    ProcessCompletion completion;
    completion.protocol_pass = protocol_pass;
    completion.exit_recorded = regular_file_exists(exit_path);
    completion.exit_zero = completion.exit_recorded &&
        result_contains(exit_path, "process.exit_status=0");
    if (completion.protocol_pass && !completion.exit_recorded) {
        std::error_code error;
        const auto written =
            std::filesystem::last_write_time(result_path, error);
        completion.exit_timed_out = error ||
            std::filesystem::file_time_type::clock::now() - written >
                std::chrono::seconds(10);
    }
    completion.failed = regular_file_exists(failure_path) ||
        (completion.exit_recorded && !completion.exit_zero) ||
        completion.exit_timed_out;
    completion.accepted = completion.protocol_pass &&
        completion.exit_recorded && completion.exit_zero;
    return completion;
}

std::string_view completion_label(const ProcessCompletion &completion) {
    if (completion.accepted) {
        return "PASS";
    }
    if (completion.failed) {
        return "FAILED";
    }
    if (completion.protocol_pass) {
        return "finishing (awaiting process exit)";
    }
    return "not complete";
}

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
    const std::filesystem::path &path, bool read_only = false) {
    RoleProcessSnapshot result;
    std::error_code error;
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path, error);
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

    int flags = (read_only ? O_RDONLY : O_RDWR) | O_CLOEXEC;
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
        ::flock(descriptor, LOCK_UN);
    } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
        result.state = RoleProcessState::Active;
    } else {
        result.state = RoleProcessState::Invalid;
        result.diagnostic = "activity lock cannot be inspected";
    }
    ::close(descriptor);
    result.last_line = last_complete_line(path);
    return result;
}

std::optional<std::string_view> progress_json_value(
    std::string_view line, std::string_view key) {
    const std::string marker = "\"" + std::string(key) + "\":";
    const std::size_t marker_position = line.find(marker);
    if (marker_position == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t begin = marker_position + marker.size();
    if (begin >= line.size()) {
        return std::nullopt;
    }
    if (line[begin] == '"') {
        ++begin;
        const std::size_t end = line.find('"', begin);
        if (end == std::string_view::npos) {
            return std::nullopt;
        }
        return line.substr(begin, end - begin);
    }
    const std::size_t end = line.find_first_of(",}", begin);
    return line.substr(begin, end == std::string_view::npos
                                  ? line.size() - begin
                                  : end - begin);
}

std::string progress_elapsed(std::string_view milliseconds) {
    std::istringstream input{std::string(milliseconds)};
    double value = 0;
    input >> value;
    if (!input || value < 0) {
        return "unknown elapsed time";
    }
    const auto total_seconds = static_cast<std::uint64_t>(value / 1000.0);
    const std::uint64_t hours = total_seconds / 3600U;
    const std::uint64_t minutes = (total_seconds / 60U) % 60U;
    const std::uint64_t seconds = total_seconds % 60U;
    std::ostringstream output;
    output << std::setfill('0') << std::setw(2) << hours << ':'
           << std::setw(2) << minutes << ':' << std::setw(2) << seconds;
    return output.str();
}

std::string readable_activity_stage(std::string stage) {
    std::replace(stage.begin(), stage.end(), '_', ' ');
    return stage;
}

void print_role_process(std::string_view role,
                        const RoleProcessSnapshot &process,
                        bool terminal_artifact) {
    std::cout << "  " << role << " process: ";
    switch (process.state) {
    case RoleProcessState::Missing:
        std::cout << (terminal_artifact ? "finished" : "not started");
        break;
    case RoleProcessState::Active:
        std::cout << "ACTIVE";
        break;
    case RoleProcessState::Inactive:
        std::cout << (terminal_artifact
                          ? "finished"
                          : "NOT RUNNING (incomplete; it may have been "
                            "interrupted or abandoned)");
        break;
    case RoleProcessState::Invalid:
        std::cout << "unknown (" << process.diagnostic << ')';
        break;
    }
    if (process.last_line) {
        if (const auto stage =
                progress_json_value(*process.last_line, "stage")) {
            std::cout << "; last stage: "
                      << readable_activity_stage(std::string(*stage));
        }
    }
    std::cout << '\n';
}

void print_server_progress(const std::filesystem::path &path,
                           const RoleProcessSnapshot &server_process) {
    bool payload_evaluation_active =
        server_process.state == RoleProcessState::Active;
    if (server_process.last_line) {
        if (const auto stage =
                progress_json_value(*server_process.last_line, "stage")) {
            payload_evaluation_active =
                payload_evaluation_active &&
                *stage == "payload_evaluation";
        }
    } else {
        payload_evaluation_active = false;
    }
    const std::optional<std::string> line = last_complete_line(path);
    if (!line) {
        if (payload_evaluation_active) {
            std::cout << "  server sumcheck: has not started; payload "
                         "evaluation is in progress\n";
        }
        return;
    }
    const auto event = progress_json_value(*line, "event");
    const auto stage = progress_json_value(*line, "stage");
    const auto status = progress_json_value(*line, "status");
    const auto elapsed = progress_json_value(*line, "run_elapsed_ms");
    const auto layer_kind = progress_json_value(*line, "layer_kind");
    const auto coordinate_domain =
        progress_json_value(*line, "coordinate_domain");
    const auto subpass = progress_json_value(*line, "subpass");
    const auto reduction = progress_json_value(*line, "reduction_layer");
    const auto source = progress_json_value(*line, "source_layer");
    const auto output_layer = progress_json_value(*line, "output_layer");
    const auto checkpoint = progress_json_value(*line, "checkpoint_layer");
    const auto side = progress_json_value(*line, "side");
    const auto round = progress_json_value(*line, "round");
    const auto rounds = progress_json_value(*line, "rounds");
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

    const auto work_units = progress_json_value(*line, "work_units");
    const auto completed_steps =
        progress_json_value(*line, "completed_steps");
    const auto total_steps = progress_json_value(*line, "total_steps");
    const auto completed_work_units =
        progress_json_value(*line, "completed_work_units");
    const auto total_work_units =
        progress_json_value(*line, "total_work_units");
    const auto progress_work_unit =
        progress_json_value(*line, "progress_work_unit");
    const auto phase_completed_steps =
        progress_json_value(*line, "phase_completed_steps");
    const auto phase_total_steps =
        progress_json_value(*line, "phase_total_steps");
    const auto completed_read_bytes =
        progress_json_value(*line, "completed_read_bytes");
    const auto total_read_bytes =
        progress_json_value(*line, "total_read_bytes");
    const auto completed_write_bytes =
        progress_json_value(*line, "completed_write_bytes");
    const auto total_write_bytes =
        progress_json_value(*line, "total_write_bytes");
    const auto phase_completed_read_bytes =
        progress_json_value(*line, "phase_completed_read_bytes");
    const auto phase_total_read_bytes =
        progress_json_value(*line, "phase_total_read_bytes");
    const auto phase_completed_write_bytes =
        progress_json_value(*line, "phase_completed_write_bytes");
    const auto phase_total_write_bytes =
        progress_json_value(*line, "phase_total_write_bytes");
    const auto completed_butterflies =
        progress_json_value(*line, "completed_butterflies");
    const auto total_butterflies =
        progress_json_value(*line, "total_butterflies");
    const auto phase_completed_butterflies =
        progress_json_value(*line, "phase_completed_butterflies");
    const auto phase_total_butterflies =
        progress_json_value(*line, "phase_total_butterflies");
    const auto radix_elements =
        progress_json_value(*line, "radix_elements");
    const auto row_count = progress_json_value(*line, "row_count");
    const auto row_size = progress_json_value(*line, "row_size");
    const auto recent_throughput =
        progress_json_value(*line, "recent_work_units_per_second");
    const auto estimated_remaining =
        progress_json_value(*line, "estimated_remaining_ms");
    const auto column_index =
        progress_json_value(*line, "column_index");
    const auto column_count =
        progress_json_value(*line, "column_count");
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
            std::cout << "current-pass " << *completed_work_units << " of "
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
                      << *completed_read_bytes << " of " << *total_read_bytes;
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
                                    progress_json_value);
    if (payload_evaluation_active) {
        std::cout << "  server sumcheck: has not started; payload "
                     "evaluation is in progress\n";
    }
}

int run_process_status(const ProcessCommand &command) {
    std::error_code run_error;
    if (!std::filesystem::is_directory(command.run_directory, run_error) ||
        run_error) {
        throw std::invalid_argument(
            "status requires an existing run directory created by setup");
    }
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    const std::filesystem::path setup_bin =
        command.run_directory / "shared" / "setup.bin";
    const std::filesystem::path setup_result =
        command.run_directory / "shared" / "setup-result.txt";
    const std::filesystem::path setup_exit =
        command.run_directory / "shared" / "setup-process-exit.txt";
    const std::filesystem::path request =
        command.run_directory / "shared" / "transcript" /
        "cli-to-srv-request.bin";
    const std::filesystem::path server_result =
        command.run_directory / "server" / "result.txt";
    const std::filesystem::path server_exit =
        command.run_directory / "server" / "process-exit.txt";
    const std::filesystem::path response =
        command.run_directory / "shared" / "transcript" /
        "srv-to-cli-response.bin";
    const std::filesystem::path client_result =
        command.run_directory / "client" / "result.txt";
    const std::filesystem::path client_exit =
        command.run_directory / "client" / "process-exit.txt";
    const std::filesystem::path server_progress =
        command.run_directory / "server" / "progress.jsonl";
    const std::filesystem::path server_activity =
        command.run_directory / "server" / "activity.jsonl";
    const std::filesystem::path client_activity =
        command.run_directory / "client" / "activity.jsonl";
    const std::filesystem::path setup_failure =
        command.run_directory / "shared" / "setup-failure.txt";
    const std::filesystem::path setup_activity =
        command.run_directory / "shared" / "setup-activity.jsonl";
    const std::filesystem::path server_failure =
        command.run_directory / "server" / "failure.txt";
    const std::filesystem::path client_failure =
        command.run_directory / "client" / "failure.txt";
    if (regular_file_exists(setup_bin)) {
        (void)load_process_setup(command);
    }

    const bool setup_protocol_pass = regular_file_exists(setup_bin) &&
        result_contains(setup_result, "setup.result=PASS");
    const ProcessCompletion setup_completion = inspect_process_completion(
        setup_protocol_pass, setup_result, setup_exit, setup_failure);
    const bool request_ready = regular_file_exists(request);
    const bool server_protocol_pass =
        result_contains(server_result, "server.result=PASS");
    const ProcessCompletion server_completion = inspect_process_completion(
        server_protocol_pass, server_result, server_exit, server_failure);
    const bool response_ready = regular_file_exists(response);
    const bool client_protocol_pass =
        result_contains(client_result, "verification.result=PASS");
    const ProcessCompletion client_completion = inspect_process_completion(
        client_protocol_pass, client_result, client_exit, client_failure);
    const bool setup_pass = setup_completion.accepted;
    const bool server_pass = server_completion.accepted;
    const bool client_pass = client_completion.accepted;
    const bool setup_failed = setup_completion.failed;
    const bool server_failed = server_completion.failed;
    const bool client_failed = client_completion.failed;
    const RoleProcessSnapshot setup_process =
        inspect_role_process(setup_activity);
    const RoleProcessSnapshot server_process =
        inspect_role_process(server_activity);
    const RoleProcessSnapshot client_process =
        inspect_role_process(client_activity);
    const bool server_terminal = server_pass || server_failed;
    const bool client_terminal = client_pass || client_failed;
    const bool role_abandoned =
        (setup_process.state == RoleProcessState::Inactive &&
         !setup_pass && !setup_completion.protocol_pass) ||
        (server_process.state == RoleProcessState::Inactive &&
         !server_terminal && !server_completion.protocol_pass) ||
        (client_process.state == RoleProcessState::Inactive &&
         !client_terminal && !client_completion.protocol_pass);
    const bool role_active =
        setup_process.state == RoleProcessState::Active ||
        server_process.state == RoleProcessState::Active ||
        client_process.state == RoleProcessState::Active;
    const bool role_invalid =
        setup_process.state == RoleProcessState::Invalid ||
        server_process.state == RoleProcessState::Invalid ||
        client_process.state == RoleProcessState::Invalid;
    const bool role_finishing =
        (server_completion.protocol_pass &&
         !server_completion.exit_recorded &&
         !server_completion.exit_timed_out) ||
        (client_completion.protocol_pass &&
         !client_completion.exit_recorded &&
         !client_completion.exit_timed_out);

    std::cout << "Laminate Base " << command.profile << " status\n"
              << "  setup: "
              << completion_label(setup_completion)
              << "\n  client request: "
              << (request_ready ? "published" : "not published")
              << "\n  server: "
              << completion_label(server_completion)
              << "\n  server response: "
              << (response_ready ? "published" : "not published")
              << "\n  client verification: "
              << completion_label(client_completion)
              << '\n';
    print_role_process("setup", setup_process,
                       setup_pass || setup_failed);
    print_role_process("client", client_process, client_terminal);
    print_role_process("server", server_process, server_terminal);
    print_server_progress(server_progress, server_process);
    int status_code = 0;
    if (role_invalid) {
        status_code = 1;
        std::cout << "\nFAILED: an activity marker cannot be inspected "
                     "safely. This run is not accepted; inspect the role "
                     "status above.\n";
    } else if (client_pass && server_pass && setup_pass) {
        std::cout << "\nCOMPLETE AND ACCEPTED: the separate client "
                     "verified the server response.\n"
                  << "Run: benches/run_gcp.sh summary base "
                  << command.profile << " "
                  << command.run_directory << '\n';
    } else if (setup_failed) {
        status_code = 1;
        std::cout << "\nFAILED: inspect shared/setup-failure.txt and "
                     "shared/setup-process-exit.txt. This run is immutable; "
                     "start a fresh run directory after correcting the "
                     "cause.\n";
    } else if (server_failed || client_failed) {
        status_code = 1;
        std::cout << "\nFAILED: inspect the matching failure.txt, "
                     "process-exit.txt, and role console.log. This run is "
                     "immutable; start a fresh run directory after "
                     "correcting the cause.\n";
    } else if (role_abandoned) {
        status_code = 1;
        std::cout << "\nINCOMPLETE AND NOT RUNNING: a started role has no "
                     "PASS or failure artifact and no longer holds its "
                     "activity lock. It may have been interrupted or "
                     "abandoned. Inspect its last stage before starting a "
                     "fresh immutable run directory.\n";
    } else if (role_finishing ||
               (setup_completion.protocol_pass &&
                !setup_completion.exit_recorded &&
                !setup_completion.exit_timed_out)) {
        std::cout << "\nFINISHING: a role published protocol PASS and is "
                     "still recording its OS process exit status. Final "
                     "acceptance requires exit status zero.\n";
    } else if (response_ready && !client_pass) {
        std::cout << "\nNOT YET ACCEPTED: a response exists, but only a "
                     "client verification PASS completes the run.\n";
    } else if (role_active) {
        std::cout << "\nRUNNING OR WAITING: at least one role still holds "
                     "its activity lock. The last stage above says whether "
                     "it is doing work or waiting for its peer.\n";
    } else {
        std::cout << "\nThe run is incomplete, and no active role has been "
                     "observed yet. Start the missing client or server "
                     "process.\n";
    }
    return status_code;
}

void publish_process_failure(const ProcessCommand &command,
                             std::string_view message) noexcept {
    try {
        std::filesystem::path path;
        std::filesystem::path activity_path;
        std::filesystem::path completed_result_path;
        std::string_view completed_result_line;
        switch (command.action) {
        case ProcessAction::Setup:
            path = command.run_directory / "shared" / "setup-failure.txt";
            activity_path =
                command.run_directory / "shared" / "setup-activity.jsonl";
            completed_result_path =
                command.run_directory / "shared" / "setup-result.txt";
            completed_result_line = "setup.result=PASS";
            break;
        case ProcessAction::RunClient:
            path = command.run_directory / "client" / "failure.txt";
            activity_path =
                command.run_directory / "client" / "activity.jsonl";
            completed_result_path =
                command.run_directory / "client" / "result.txt";
            completed_result_line = "verification.result=PASS";
            break;
        case ProcessAction::RunServer:
            path = command.run_directory / "server" / "failure.txt";
            activity_path =
                command.run_directory / "server" / "activity.jsonl";
            completed_result_path =
                command.run_directory / "server" / "result.txt";
            completed_result_line = "server.result=PASS";
            break;
        case ProcessAction::Status:
        case ProcessAction::VerifySavedResponse:
            return;
        }
        if (!std::filesystem::is_directory(path.parent_path())) {
            return;
        }
        if (!completed_result_path.empty() &&
            result_contains(completed_result_path,
                            completed_result_line)) {
            return;
        }
        // A duplicate invocation must not poison the original live role.
        // The failing role's own lock has already been released by stack
        // unwinding before this handler runs, so ACTIVE can only mean that a
        // different process owns this role.
        if (!activity_path.empty() &&
            inspect_role_process(activity_path).state ==
                RoleProcessState::Active) {
            return;
        }
        const std::string contents = "FAILED: " + std::string(message) + '\n';
        publish_private_file(
            path,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(contents.data()),
                contents.size()));
    } catch (...) {
        // Preserve the original protocol or I/O exception.
    }
}

struct LoadedProcessInputs {
    ProcessProfile selected;
    Options options;
    RunProfile profile;
    LayeredCircuit circuit;
    ProcessSetupRecord stored;
    DiagnosticPreflight preflight;
};

struct LoadedClientProcessInputs {
    ProcessProfile selected;
    std::vector<SlotVector> inputs;
    SealParameters seal_parameters;
    ProcessSetupRecord stored;
    BaseWireDecodeLimits wire_limits;
    protocol::CertifiedBaseClientSetup<SealBackend> client;
    Timing preprocessing_load_timing;
};

void require_completed_process_setup(const ProcessCommand &command) {
    const std::filesystem::path setup_result =
        command.run_directory / "shared" / "setup-result.txt";
    const std::filesystem::path setup_exit =
        command.run_directory / "shared" / "setup-process-exit.txt";
    if (!result_contains(setup_result, "setup.result=PASS") ||
        !result_contains(setup_exit, "process.exit_status=0")) {
        throw std::runtime_error(
            "online roles require setup.result=PASS and setup process exit "
            "status zero");
    }
}

using ProcessLoadStageCallback =
    std::function<void(std::string_view)>;

enum class ClientProcessLoadMode {
    Online,
    SavedResponseDiagnostic,
};

SealParameters validated_process_client_seal_parameters(
    const SealParameters &stored, const ProcessProfile &selected,
    const Options &options, ClientProcessLoadMode mode) {
    const auto current = process_client_seal_parameters(selected, options);
    if (stored == current) return current;
    if (mode == ClientProcessLoadMode::SavedResponseDiagnostic) {
        // Compatibility requires an exact match of prime order, special prime,
        // caps, and key-generation policy. These variants are read-only.
        for (const auto version : {BaseSealParameterVersion::TenDataPrimes,
                                   BaseSealParameterVersion::ElevenDataPrimes}) {
            if (stored == process_client_seal_parameters(selected, options, version))
                return stored;
        }
    }
    throw std::runtime_error(
        "client preprocessing parameters differ from the selected benchmark profile");
}

std::vector<std::uint8_t> load_role_preprocessing(
    const std::filesystem::path &path, std::uint64_t expected_bytes,
    const Digest &expected_digest);

LoadedProcessInputs load_process_inputs(
    const ProcessCommand &command,
    const ProcessLoadStageCallback &stage = {}) {
    const auto transition = [&](std::string_view value) {
        if (stage) {
            stage(value);
        }
    };
    require_completed_process_setup(command);
    transition("reconstructing_workload_profile");
    ProcessProfile selected = process_profile(command.profile);
    transition("reading_setup_record");
    ProcessSetupRecord stored = load_process_setup(command);
    require_process_build_match(stored);
    Options options = process_options(
        command, selected, require_bound_host_budget(stored));
    RunProfile profile = make_run_profile(options);
    transition("compiling_circuit");
    LayeredCircuit circuit = compile(profile.payload);
    transition("deriving_certified_schedule");
    CertifiedHonestPayloadSchedule schedule = restore_process_schedule(
        stored, profile, circuit, selected.proof_ingress_rns_limbs);
    transition("verifying_setup_binding");
    PublicSetup public_setup = restore_process_public_setup(
        stored, profile.payload, circuit, schedule);
    transition("rebuilding_replay_capacity");
    DiagnosticPreflight preflight = finish_diagnostic_preflight(
        options, profile, circuit, std::move(schedule),
        std::move(public_setup));
    require(preflight.replay_budgets == stored.replay_budgets,
            "server replay budget does not match immutable setup.bin");
    require(preflight.client_peak_resident_bytes_upper ==
                stored.client_peak_resident_bytes,
            "server client-resident reserve does not match immutable "
            "setup.bin");
    require(base_replay_plan_digest(preflight.replay_plan) ==
                stored.replay_plan_digest,
            "server replay plan does not match immutable setup.bin");
    return LoadedProcessInputs{
        std::move(selected), std::move(options), std::move(profile),
        std::move(circuit), std::move(stored), std::move(preflight)};
}

LoadedClientProcessInputs load_client_process_inputs(
    const ProcessCommand &command,
    const ProcessLoadStageCallback &stage = {},
    ClientProcessLoadMode mode = ClientProcessLoadMode::Online) {
    const auto transition = [&](std::string_view value) {
        if (stage) {
            stage(value);
        }
    };
    require_completed_process_setup(command);
    ProcessProfile selected = process_profile(command.profile);
    transition("reading_setup_record");
    ProcessSetupRecord stored = load_process_setup(command);
    if (mode == ClientProcessLoadMode::Online) {
        require_process_build_match(stored);
    } else {
        require(command.action == ProcessAction::VerifySavedResponse,
                "cross-revision client loading is diagnostic-only");
        require(stored.build_type == "Release" &&
                    stored.git_commit.size() == 40 &&
                    std::all_of(stored.git_commit.begin(), stored.git_commit.end(),
                        [](char c) { return (c >= '0' && c <= '9') ||
                                            (c >= 'a' && c <= 'f'); }),
                "saved-response diagnostic requires recorded Release preprocessing");
        // Preserve the original authenticated schedule digest. This path
        // verifies an existing statement; it does not derive a new schedule
        // or admit a new benchmark run under the current executable.
    }
    Options options = process_options(
        command, selected, require_bound_host_budget(stored));
    transition("preparing_benchmark_inputs");
    std::vector<SlotVector> inputs = make_workload_inputs(
        diagnostic_workload_spec(options.diagnostic));
    Stopwatch preprocessing_stopwatch;
    (void)require_process_client_preprocessing_bound(options, stored);
    transition("reading_client_static_preprocessing");
    std::vector<std::uint8_t> static_bytes = read_bounded_file(
        command.run_directory / "client" / "preprocessing" /
            "client-static.bin",
        stored.client_static_bytes);
    if (static_bytes.size() != stored.client_static_bytes) {
        throw std::runtime_error(
            "client static preprocessing has the wrong size");
    }
    transition("authenticating_client_static_preprocessing");
    protocol::AuthenticatedBaseClientStaticSetup authenticated_static =
        protocol::decode_authenticated_base_client_static_setup(
            static_bytes, stored.client_static_digest,
            stored.public_setup_digest, stored.circuit_digest,
            process_client_static_decode_limits(
                selected, options, stored));
    std::vector<std::uint8_t>().swap(static_bytes);
    transition("restoring_client_public_setup");
    PublicSetup public_setup = restore_process_client_public_setup(
        stored, authenticated_static.payload_shape(),
        authenticated_static.layer_count(),
        selected.proof_ingress_rns_limbs);
    transition("reading_client_fhe_context");
    std::vector<std::uint8_t> context_bytes = load_role_preprocessing(
        command.run_directory / "client" / "preprocessing" /
            "client.bin",
        stored.client_context_bytes, stored.client_context_digest);
    transition("deserializing_client_fhe_context");
    SealBackend::ClientContext context =
        SealBackend::deserialize_client_context_bundle(context_bytes);
    std::vector<std::uint8_t>().swap(context_bytes);
    SealParameters seal_parameters = validated_process_client_seal_parameters(
        context.parameters, selected, options, mode);
    if (NaturalMagnitude::product(context.parameters.exact_data_primes)
            .bit_count() != stored.fresh_modulus_product_bits) {
        throw std::runtime_error(
            "client preprocessing modulus differs from immutable "
            "setup.bin");
    }
    transition("restoring_certified_client_state");
    ClientSetup<SealBackend> raw_client = make_client_setup<SealBackend>(
        std::move(public_setup), std::move(context));
    protocol::CertifiedBaseClientSetup<SealBackend> client =
        protocol::restore_base_client_setup<SealBackend>(
            std::move(authenticated_static), std::move(raw_client));
    const Timing preprocessing_load_timing =
        preprocessing_stopwatch.stop();
    if (client.setup_id() != stored.public_setup_digest ||
        client.circuit_id() != stored.circuit_digest) {
        throw std::runtime_error(
            "certified client statement differs from immutable setup.bin");
    }
    require_process_client_profile_geometry(selected, client);
    BaseWireDecodeLimits wire_limits = stored.client_wire_limits;
    return LoadedClientProcessInputs{
        std::move(selected), std::move(inputs),
        std::move(seal_parameters),
        std::move(stored), std::move(wire_limits), std::move(client),
        preprocessing_load_timing};
}

std::vector<std::uint8_t> load_role_preprocessing(
    const std::filesystem::path &path, std::uint64_t expected_bytes,
    const Digest &expected_digest) {
    std::vector<std::uint8_t> bytes =
        read_bounded_file(path, expected_bytes);
    if (bytes.size() != expected_bytes || sha256(bytes) != expected_digest) {
        throw std::runtime_error(
            "role preprocessing differs from immutable setup.bin");
    }
    return bytes;
}

void emit_process_geometry(const Record &record,
                           const LoadedProcessInputs &loaded) {
    const BenchmarkPayloadProfile payload_profile =
        benchmark_payload_profile(loaded.selected.name);
    record.integer("parameters.slots", loaded.circuit.shape.slot_count);
    record.integer("parameters.payload_multiplicative_depth",
                   loaded.selected.multiplicative_depth);
    record.text("parameters.payload_workload",
                std::string(workload_name(payload_profile.workload_kind)));
    record.integer("parameters.payload_width",
                   loaded.selected.middle_width);
    record.integer("parameters.payload_inputs",
                   loaded.profile.payload.input_count);
    record.integer("parameters.payload_outputs",
                   loaded.profile.payload.outputs.size());
    record.integer("parameters.payload_operations",
                   loaded.profile.payload.gates.size());
    record.integer("parameters.payload_add_gates",
                   payload_profile.add_gates);
    record.integer("parameters.payload_add_plain_gates",
                   payload_profile.add_plain_gates);
    record.integer("parameters.payload_mul_gates",
                   payload_profile.mul_gates);
    record.integer("parameters.payload_mul_plain_gates",
                   payload_profile.mul_plain_gates);
    record.integer("parameters.payload_rotate_gates",
                   payload_profile.rotate_gates);
    record.integer("parameters.compiled_layers",
                   loaded.circuit.layers.size());
    record.integer("parameters.initial_ciphertext_modulus_bits",
                   loaded.preflight.schedule().fresh_modulus_product_bits);
    record.text("parameters.initial_ciphertext_modulus_primes",
                decimal_list(
                    loaded.profile.seal_parameters.exact_data_primes));
    record.integer("parameters.fresh_rns_limbs",
                   loaded.profile.seal_parameters.fresh_rns_limbs);
    record.text("parameters.base_proof_schedule_policy",
                loaded.stored.proof_schedule_policy);
    record.text("parameters.base_payload_noise_model",
                std::string(loaded.preflight.schedule().payload_noise_model));
    record.integer("parameters.base_proof_ingress_rns_limbs",
                   loaded.stored.proof_ingress_rns_limbs);
}

void emit_process_geometry(const Record &record,
                           const LoadedClientProcessInputs &loaded) {
    const BenchmarkPayloadProfile payload_profile =
        benchmark_payload_profile(loaded.selected.name);
    const LayeredCircuit &circuit = loaded.client.circuit();
    const PayloadCircuit &payload = loaded.client.payload();
    record.integer("parameters.slots", circuit.shape.slot_count);
    record.integer("parameters.payload_multiplicative_depth",
                   loaded.selected.multiplicative_depth);
    record.text("parameters.payload_workload",
                std::string(workload_name(payload_profile.workload_kind)));
    record.integer("parameters.payload_width",
                   loaded.selected.middle_width);
    record.integer("parameters.payload_inputs", payload.input_count);
    record.integer("parameters.payload_outputs", payload.outputs.size());
    record.integer("parameters.payload_operations", payload.gates.size());
    record.integer("parameters.payload_add_gates",
                   payload_profile.add_gates);
    record.integer("parameters.payload_add_plain_gates",
                   payload_profile.add_plain_gates);
    record.integer("parameters.payload_mul_gates",
                   payload_profile.mul_gates);
    record.integer("parameters.payload_mul_plain_gates",
                   payload_profile.mul_plain_gates);
    record.integer("parameters.payload_rotate_gates",
                   payload_profile.rotate_gates);
    record.integer("parameters.compiled_layers", circuit.layers.size());
    record.integer("parameters.initial_ciphertext_modulus_bits",
                   loaded.stored.fresh_modulus_product_bits);
    record.text("parameters.initial_ciphertext_modulus_primes",
                decimal_list(
                    loaded.seal_parameters.exact_data_primes));
    record.integer("parameters.fresh_rns_limbs",
                   loaded.seal_parameters.fresh_rns_limbs);
    record.text("parameters.base_proof_schedule_policy",
                loaded.stored.proof_schedule_policy);
    record.text("parameters.base_payload_noise_model",
                std::string(kDependencyAwareHonestPayloadNoiseModelV1));
    record.integer("parameters.base_proof_ingress_rns_limbs",
                   loaded.stored.proof_ingress_rns_limbs);
}

Timing add_timings(std::initializer_list<Timing> values) {
    Timing result;
    for (const Timing &value : values) {
        result.wall_ms += value.wall_ms;
        result.cpu_ms += value.cpu_ms;
    }
    return result;
}

std::optional<std::string> published_failure(
    const std::filesystem::path &path) {
    std::error_code error;
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory ||
        (!error && status.type() ==
                       std::filesystem::file_type::not_found)) {
        return std::nullopt;
    }
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error(
            "peer failure path is not a safe regular file: " +
            path.string());
    }
    const std::vector<std::uint8_t> bytes =
        read_bounded_file(path, 16U << 10U);
    return std::string(reinterpret_cast<const char *>(bytes.data()),
                       bytes.size());
}

Timing wait_for_artifact(
    const std::filesystem::path &path, std::string_view role,
    std::string_view artifact_description, RoleActivity &activity,
    std::string_view waiting_stage,
    const std::filesystem::path &peer_failure_path,
    const std::filesystem::path &peer_activity_path) {
    Stopwatch stopwatch;
    activity.transition(waiting_stage);
    auto next_notice = std::chrono::steady_clock::now() +
                       std::chrono::seconds(60);
    std::optional<std::chrono::steady_clock::time_point>
        peer_inactive_since;
    while (true) {
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        if (!error && std::filesystem::is_regular_file(status)) {
            return stopwatch.stop();
        }
        if (error && error != std::errc::no_such_file_or_directory) {
            throw std::runtime_error(
                "cannot inspect expected artifact path: " +
                path.string());
        }
        if (!error && status.type() !=
                          std::filesystem::file_type::not_found) {
            throw std::runtime_error(
                "expected artifact path is not a regular file: " +
                path.string());
        }

        if (const auto failure = published_failure(peer_failure_path)) {
            throw std::runtime_error(
                "peer failed while waiting for " +
                std::string(artifact_description) + ": " + *failure);
        }

        const auto now = std::chrono::steady_clock::now();
        const RoleProcessSnapshot peer =
            inspect_role_process(peer_activity_path);
        if (peer.state == RoleProcessState::Invalid) {
            throw std::runtime_error(
                "cannot safely inspect peer activity while waiting for " +
                std::string(artifact_description) + ": " +
                peer.diagnostic);
        }
        if (peer.state == RoleProcessState::Inactive) {
            if (!peer_inactive_since) {
                peer_inactive_since = now;
            } else if (now - *peer_inactive_since >=
                       std::chrono::seconds(3)) {
                throw std::runtime_error(
                    "peer is no longer running and did not publish " +
                    std::string(artifact_description));
            }
        } else {
            peer_inactive_since.reset();
        }
        activity.heartbeat();
        if (now >= next_notice) {
            const std::uint64_t total_seconds =
                static_cast<std::uint64_t>(stopwatch.stop().wall_ms / 1000.0);
            const std::uint64_t hours = total_seconds / 3600U;
            const std::uint64_t minutes = (total_seconds / 60U) % 60U;
            const std::uint64_t seconds = total_seconds % 60U;
            std::cerr << role << ": idle; waiting for "
                      << artifact_description << " (elapsed "
                      << std::setfill('0') << std::setw(2) << hours << ':'
                      << std::setw(2) << minutes << ':' << std::setw(2)
                      << seconds << std::setfill(' ') << ")\n";
            next_notice = now + std::chrono::seconds(60);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

BaseClientNonce fresh_process_nonce() {
    std::array<std::uint8_t, 64> entropy{};
    std::random_device source;
    for (std::uint8_t &byte : entropy) {
        byte = static_cast<std::uint8_t>(source());
    }
    return make_base_client_nonce(entropy);
}

constexpr std::string_view kProcessTranscriptDomain =
    "LaminateImpl/Bench/BaseRoleSeparated/v1";

// Unlike an online role, this reader must never create a lock in its source.
class SavedResponseSourceLock {
  public:
    explicit SavedResponseSourceLock(const std::filesystem::path &source) {
        require(std::filesystem::canonical(source) == source,
                "saved-response source must be a canonical absolute directory");
        for (const char *relative : {"", "shared", "shared/transcript",
                                    "client", "client/preprocessing", "server"}) {
            struct stat metadata {};
            const auto path = source / relative;
            require(::lstat(path.c_str(), &metadata) == 0 &&
                        S_ISDIR(metadata.st_mode) && metadata.st_uid == ::geteuid() &&
                        (metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0,
                    "saved-response source contains an unsafe directory");
        }
        const auto path = source / "shared/lifecycle.lock";
        descriptor_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor_ < 0)
            throw std::system_error(errno, std::generic_category(),
                                    "cannot open existing saved-response lifecycle lock");
        struct stat metadata {};
        if (::fstat(descriptor_, &metadata) != 0 ||
            !S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
            (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
            ::flock(descriptor_, LOCK_EX | LOCK_NB) != 0) {
            ::close(descriptor_);
            descriptor_ = -1;
            throw std::runtime_error(
                "saved-response source is active or its lifecycle lock is unsafe");
        }
    }
    SavedResponseSourceLock(const SavedResponseSourceLock &) = delete;
    SavedResponseSourceLock &operator=(const SavedResponseSourceLock &) = delete;
    ~SavedResponseSourceLock() {
        if (descriptor_ >= 0) {
            (void)::flock(descriptor_, LOCK_UN);
            (void)::close(descriptor_);
        }
    }
  private:
    int descriptor_ = -1;
};

void require_saved_response_output_directory(const ProcessCommand &command) {
    const auto &destination = command.output_directory;
    require(destination.is_absolute() && destination == destination.lexically_normal() &&
                destination != destination.root_path() &&
                std::filesystem::canonical(destination.parent_path()) == destination.parent_path(),
            "saved-response output must have a canonical existing parent");
    const auto contains = [](const auto &parent, const auto &child) {
        return std::mismatch(parent.begin(), parent.end(), child.begin(), child.end()).first ==
               parent.end();
    };
    require(!contains(command.run_directory, destination) &&
                !contains(destination, command.run_directory),
            "saved-response source and output must be disjoint");
    std::error_code error;
    const auto status = std::filesystem::symlink_status(destination, error);
    require(error == std::errc::no_such_file_or_directory ||
                (!error && status.type() == std::filesystem::file_type::not_found),
            "saved-response output directory must not already exist");
}

void require_saved_response_failure(const ProcessCommand &command) {
    require_completed_process_setup(command);
    require(result_contains(command.run_directory / "server/result.txt", "server.result=PASS") &&
                result_contains(command.run_directory / "server/process-exit.txt", "process.exit_status=0"),
            "saved-response diagnostic requires a completed server response");
    require(result_contains(command.run_directory / "client/process-exit.txt", "process.exit_status=1"),
            "saved-response diagnostic requires the recorded client failure");
    const auto bytes = read_bounded_file(command.run_directory / "client/failure.txt", 4096);
    const std::string failure(bytes.begin(), bytes.end());
    // These exact failures admit inspection of the original authenticated
    // request and response, never a resumed client role or repaired proof.
    require(failure == "FAILED: decode_base_response: Wide public target values exceed limit\n" ||
                failure == "FAILED: client verification FAILED at affine-reduction | layer 0 | "
                           "terminal identity failed: sum GateMLE*W != reduced claim "
                           "(a corrupt operand, e.g. exhausted noise budget, produces exactly this)\n",
            "saved-response diagnostic requires the known Wide public-target decode-limit "
            "or first-affine terminal-identity failure");
    for (const auto *relative : {"shared/setup-activity.jsonl", "client/activity.jsonl",
                                 "server/activity.jsonl"})
        require(inspect_role_process(command.run_directory / relative, true).state == RoleProcessState::Inactive,
                "saved-response source role is active or lacks intact activity evidence");
}

BaseWireDecodeLimits saved_response_decode_limits(
    const ProcessSetupRecord &stored) {
    require(stored.gate_mle_verifier.has_value() &&
                stored.gate_mle_verifier->layout.table_set == gates::GateTableSet::Wide,
            "saved-response diagnostic requires authenticated Wide GateMLE preprocessing");
    const auto &key = *stored.gate_mle_verifier;
    const auto requests = checked_size(checked_multiply_u64(
        24U, std::max<std::size_t>(1, key.layout.wide_layers.size()),
        "saved-response Wide request count"), "saved-response Wide request count");
    std::size_t maximum_width = 0;
    for (const auto &table : key.tables)
        maximum_width = std::max(maximum_width, table.physical_width);
    const auto legacy = checked_size(checked_multiply_u64(
        requests, maximum_width, "legacy Wide target limit"), "legacy Wide target limit");
    const auto corrected = base_wire_detail::gate_target_values_upper_bound(key, requests);
    require(corrected <= (std::size_t{1} << 24U),
            "corrected Wide public-target bound exceeds the setup codec hard limit");
    BaseWireDecodeLimits result = stored.client_wire_limits;
    require(result.max_gate_target_values == legacy ||
                result.max_gate_target_values == corrected,
            "stored Wide public-target limit is neither the known legacy nor corrected bound");
    result.max_gate_target_values = corrected;
    return result;
}

template <fhe::PersistableFheBackend Backend>
BaseClientAwaitingResponse restore_saved_base_client_session(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    std::span<const SlotVector> expected_inputs,
    std::span<const std::uint8_t> request_bytes,
    const BaseWireDecodeLimits &limits) {
    const auto request = decode_base_request<Backend>(client.context(), request_bytes, limits);
    require(request.setup_id == client.setup_id() && request.circuit_id == client.circuit_id(),
            "saved request does not match authenticated client preprocessing");
    require(request.encrypted_inputs.size() == expected_inputs.size() &&
                expected_inputs.size() == client.payload().input_count,
            "saved request has the wrong benchmark input count");
    require(request.trace_id == payload::prevalidated_trace_identity::
                validated_fhe_evaluated_trace_id<Backend>(
                    client.circuit_id(), client.payload().input_count, request.encrypted_inputs),
            "saved request trace identifier does not authenticate its ciphertexts");
    for (std::size_t index = 0; index < expected_inputs.size(); ++index)
        require(Backend::decrypt(client.context(), request.encrypted_inputs[index]) == expected_inputs[index],
                "saved request plaintext differs from the original deterministic benchmark input");
    auto input_layer = payload::prevalidated_plain_trace::
        make_plain_input_layer_from_validated_circuit(client.circuit(), expected_inputs);
    return BaseClientAwaitingResponse{
        request.setup_id, request.session_id, request.circuit_id, request.trace_id,
        base_request_commitment<Backend>(request), std::move(input_layer)};
}

struct SavedResponseVerificationMeasurements {
    Timing decode_response;
    Timing open_response;
    Timing verify;
    verification_profile::VerificationBreakdown components;
    protocol::BaseVerifierTimings verifier;
};

template <fhe::PersistableFheBackend Backend>
std::size_t verify_saved_base_response(
    const protocol::CertifiedBaseClientSetup<Backend> &client,
    BaseClientAwaitingResponse state, std::vector<std::uint8_t> response_bytes,
    const BaseWireDecodeLimits &limits, const ProcessLoadStageCallback &stage = {},
    SavedResponseVerificationMeasurements *measurements = nullptr,
    const std::function<void(const BaseResponse<Backend> &,
                             const gkr::SingleClaim &, Transcript)> &failure_audit = {}) {
    SavedResponseVerificationMeasurements measured;
    if (stage) stage("decoding_saved_response");
    auto decoded = timed([&] {
        return decode_base_response<Backend>(
            client, response_bytes, limits, TraceProvenance::FheEvaluated);
    });
    auto response = std::move(decoded.first);
    measured.decode_response = decoded.second;
    std::vector<std::uint8_t>().swap(response_bytes);
    auto transcript = [&] {
        verification_profile::ScopedVerificationSession session(measured.components);
        verification_profile::ScopedVerificationPhase recovery(
            verification_profile::Category::Recovery);
        return Transcript(kProcessTranscriptDomain);
    }();
    if (stage) stage("opening_saved_response");
    auto opened = timed([&] {
        verification_profile::ScopedVerificationSession session(measured.components);
        return open_base_response<Backend>(client, std::move(state), response, transcript);
    });
    measured.open_response = opened.second;
    require(opened.first.has_value(), "saved response rejected before proof verification");
    const auto audit_claim = failure_audit
        ? std::optional<gkr::SingleClaim>(
            base_client_detail::ClientStateAccess::output_claim(*opened.first))
        : std::nullopt;
    const auto audit_transcript = failure_audit
        ? std::optional<Transcript>(transcript) : std::nullopt;
    if (stage) stage("verifying_saved_proof");
    auto verified = timed([&] {
        verification_profile::ScopedVerificationSession session(measured.components);
        return verify_opened_base_response_profiled<Backend>(
            client, std::move(*opened.first), response, transcript, measured.verifier);
    });
    measured.verify = verified.second;
    if (!verified.first) {
        const auto reason = gkr::base_detail::base_verifier_diagnostic().to_string();
        if (failure_audit) {
            try {
                failure_audit(response, *audit_claim, *audit_transcript);
            } catch (const std::exception &error) {
                std::cerr << "Saved-response failure audit could not finish: " << error.what() << '\n';
            }
        }
        if (stage) stage("verification_failed");
        throw std::runtime_error("saved response proof verification FAILED at " + reason);
    }
    require(verified.first->size() == client.payload().outputs.size(),
            "saved response verified output count differs from the benchmark");
    if (measurements) *measurements = std::move(measured);
    return verified.first->size();
}

int run_saved_response_verification(const ProcessCommand &command, int argc, char **argv) {
    Stopwatch process_stopwatch;
    const auto started = unix_milliseconds();
    SavedResponseSourceLock source_lock(command.run_directory);
    require_saved_response_output_directory(command);
    require_saved_response_failure(command);
    make_private_directory(command.output_directory);
    std::string current_stage = "loading_saved_client_preprocessing";
    const auto stage = [&](std::string_view value) {
        current_stage = value;
        std::cout << "SAVED RESPONSE: " << value << std::endl;
    };
    try {
        auto loaded = load_client_process_inputs(
            command, stage, ClientProcessLoadMode::SavedResponseDiagnostic);
        const auto run_binding = read_bounded_file(
            command.run_directory / "shared/run-binding.txt", 4096);
        require(std::string(run_binding.begin(), run_binding.end()) ==
                    "format=laminate-benchmark-run-v1\nrun.variant=base\nrun.profile=" +
                        command.profile + "\nrun.id=" + digest_hex(loaded.stored.run_id) + "\n",
                "saved-response source run binding differs from setup.bin");
        stage("validating_saved_decode_limits");
        const auto limits = saved_response_decode_limits(loaded.stored);
        CompletedResultReport provenance(command.output_directory / "provenance.txt");
        const Record identity(provenance.mirror());
        identity.text("format", "laminate-base-saved-response-diagnostic-v1");
        identity.text("source.run_directory", command.run_directory.string());
        identity.text("source.run_id", digest_hex(loaded.stored.run_id));
        identity.text("source.profile", command.profile);
        identity.text("source.git_commit", loaded.stored.git_commit);
        identity.text("source.build_type", loaded.stored.build_type);
        identity.text("source.seal_acceleration", loaded.stored.seal_acceleration);
        identity.text("source.setup_sha256", digest_hex(sha256(read_bounded_file(
            command.run_directory / "shared/setup.bin", kProcessMaximumSetupBytes))));
        identity.text("source.client_static_sha256", digest_hex(loaded.stored.client_static_digest));
        identity.text("source.client_context_sha256", digest_hex(loaded.stored.client_context_digest));
        identity.text("source.schedule_digest", digest_hex(loaded.stored.schedule_digest));
        identity.text("diagnostic.git_commit", LAMINATE_BASE_CHECKPOINT_GIT_COMMIT);
        identity.text("diagnostic.git_dirty", LAMINATE_BASE_CHECKPOINT_GIT_DIRTY);
        identity.text("diagnostic.build_type", LAMINATE_BUILD_TYPE);
        identity.text("diagnostic.seal_acceleration", LAMINATE_SEAL_ACCELERATION);
        identity.text("diagnostic.command", exact_command(argc, argv));
        identity.integer("source.max_gate_target_values", loaded.stored.client_wire_limits.max_gate_target_values);
        identity.integer("diagnostic.max_gate_target_values", limits.max_gate_target_values);
        identity.text("diagnostic.scope", "saved-response-client-remeasurement; original benchmark status unchanged");
        provenance.publish();

        // This measures the usual client encryption work with the original
        // keys. The resulting ciphertexts are discarded and never replace the
        // immutable request whose session and proof are verified below.
        stage("remeasuring_input_encryption");
        Timing encryption_timing;
        {
            const auto encrypted = timed([&] {
                return payload::prevalidated_input_encryption::
                    encrypt_wide_inputs_from_validated_payload<SealBackend>(
                        loaded.client.context(), loaded.client.payload(), loaded.inputs);
            });
            encryption_timing = encrypted.second;
        }
        stage("reading_saved_request");
        auto request = timed([&] {
            return read_bounded_file(command.run_directory / "shared/transcript/cli-to-srv-request.bin",
                                     limits.max_message_bytes);
        });
        const auto request_bytes_count = request.first.size();
        const auto request_digest = sha256(request.first);
        stage("authenticating_saved_request");
        auto restored = timed([&] {
            return restore_saved_base_client_session<SealBackend>(
                loaded.client, loaded.inputs, request.first, limits);
        });
        std::vector<std::uint8_t>().swap(request.first);
        stage("reading_saved_response");
        auto response = timed([&] {
            return read_bounded_file(command.run_directory / "shared/transcript/srv-to-cli-response.bin",
                                     limits.max_message_bytes);
        });
        const auto response_bytes_count = response.first.size();
        const auto response_digest = sha256(response.first);
        CompletedResultReport transcript_record(command.output_directory / "transcript.txt");
        const Record bindings(transcript_record.mirror());
        bindings.text("request.sha256", digest_hex(request_digest));
        bindings.text("response.sha256", digest_hex(response_digest));
        transcript_record.publish();
        SavedResponseVerificationMeasurements verification;
        const auto audit_failure = [&](const BaseResponse<SealBackend> &failed,
                                       const gkr::SingleClaim &claim,
                                       Transcript original_transcript) {
            stage("auditing_failed_proof");
            const auto diagnostic = gkr::base_detail::base_verifier_diagnostic();
            CompletedResultReport noise_report(command.output_directory / "failure-noise-audit.txt");
            const Record noise_record(noise_report.mirror());
            noise_record.text("format", "laminate-base-failed-proof-noise-audit-v1");
            noise_record.text("request.sha256", digest_hex(request_digest));
            noise_record.text("response.sha256", digest_hex(response_digest));
            noise_record.text("verification.failure", diagnostic.to_string());
            try {
                audit_base_response_noise(loaded.client.context(), failed, diagnostic.layer, noise_record);
                noise_record.text("audit.status", "complete");
            } catch (const std::exception &error) {
                noise_record.text("audit.status", "failed");
                noise_record.text("audit.error", error.what());
            }
            noise_report.publish();
            CompletedResultReport affine_report(command.output_directory / "failure-affine-audit.txt");
            const Record affine_record(affine_report.mirror());
            affine_record.text("format", "laminate-base-failed-proof-affine-audit-v1");
            affine_record.text("request.sha256", digest_hex(request_digest));
            affine_record.text("response.sha256", digest_hex(response_digest));
            affine_record.text("verification.failure", diagnostic.to_string());
            try {
                audit_saved_first_affine(loaded.client, failed, claim, std::move(original_transcript), affine_record);
                affine_record.text("audit.status", "complete");
            } catch (const std::exception &error) {
                affine_record.text("audit.status", "failed");
                affine_record.text("audit.error", error.what());
            }
            affine_report.publish();
        };
        const auto outputs = verify_saved_base_response<SealBackend>(
            loaded.client, std::move(restored.first), std::move(response.first),
            limits, stage, &verification, audit_failure);
        const auto process_timing = process_stopwatch.stop();
        const auto finished = unix_milliseconds();
        const auto client_system = system_info();
        require(client_system.peak_rss_bytes <= loaded.stored.client_peak_resident_bytes,
                "observed recovered Base client peak RSS exceeds its setup-bound reserve");
        CompletedResultReport result(command.output_directory / "result.txt");
        const Record record(result.mirror());
        record.text("format", "laminate-base-saved-response-diagnostic-v1");
        record.text("run.variant", "base");
        record.text("run.profile", command.profile);
        record.text("run.id", digest_hex(loaded.stored.run_id));
        record.text("source.run_id", digest_hex(loaded.stored.run_id));
        record.text("source.profile", command.profile);
        record.text("source.git_commit", loaded.stored.git_commit);
        record.text("source.run_directory", command.run_directory.string());
        record.text("request.sha256", digest_hex(request_digest));
        record.text("response.sha256", digest_hex(response_digest));
        emit_timing_pair(record, "timing.client.load_preprocessing", loaded.preprocessing_load_timing);
        emit_timing_pair(record, "timing.client.encrypt_inputs", encryption_timing);
        emit_timing_pair(record, "timing.client.read_response_file", response.second);
        emit_timing_pair(record, "timing.client.decode_response", verification.decode_response);
        emit_timing_pair(record, "timing.client.open_response", verification.open_response);
        emit_timing_pair(record, "timing.client.verify", verification.verify);
        emit_timing_pair(record, "timing.client.verify.decryption_and_unpack",
            Timing{verification.verifier.packed_message_verification_wall_ms,
                   verification.verifier.packed_message_verification_cpu_ms});
        emit_timing_pair(record, "timing.client.verify.gate_mle_opening",
            Timing{verification.verifier.gate_mle_opening_wall_ms,
                   verification.verifier.gate_mle_opening_cpu_ms});
        record.integer("timing.client.verify.layer_count", verification.verifier.layers.size());
        for (std::size_t index = 0; index < verification.verifier.layers.size(); ++index) {
            const auto &layer = verification.verifier.layers[index];
            const auto prefix = "timing.client.verify.layer." + std::to_string(index);
            record.integer(prefix + ".circuit_layer", layer.layer);
            record.text(prefix + ".kind", layer.kind == payload::LayerKind::Affine
                        ? "affine" : "multiplication");
            emit_timing_pair(record, prefix, Timing{layer.wall_ms, layer.cpu_ms});
        }
        const auto computation = emit_client_computation(record, encryption_timing, verification.components);
        emit_timing_pair(record, "timing.client.per_request_total", computation);
        emit_timing_pair(record, "timing.client.online_total", computation);
        record.text("timing.client.per_request_total.scope", std::string(kClientComputationScope));
        record.text("timing.client.online_total.scope", "alias-of-client-per-request-total");
        emit_timing_pair(record, "timing.recovery.read_saved_request", request.second);
        emit_timing_pair(record, "timing.recovery.authenticate_saved_request", restored.second);
        emit_timing_pair(record, "timing.recovery.process_total", process_timing);
        record.integer("timing.recovery.started_unix_ms", started);
        record.integer("timing.recovery.finished_unix_ms", finished);
        record.integer("wire.request_bytes", request_bytes_count);
        record.integer("wire.response_bytes", response_bytes_count);
        record.integer("memory.client.admitted_peak_resident_bytes", loaded.stored.client_peak_resident_bytes);
        record.integer("memory.client.peak_rss_bytes", client_system.peak_rss_bytes);
        record.text("memory.client.peak_rss_scope", "saved-response-recovery-process");
        record.text("environment.git_commit", LAMINATE_BASE_CHECKPOINT_GIT_COMMIT);
        record.text("environment.git_dirty", LAMINATE_BASE_CHECKPOINT_GIT_DIRTY);
        record.text("environment.build_type", LAMINATE_BUILD_TYPE);
        record.text("environment.compiler", LAMINATE_COMPILER);
        record.text("environment.seal_version", LAMINATE_SEAL_VERSION);
        record.text("environment.seal_acceleration", LAMINATE_SEAL_ACCELERATION);
        record.text("environment.sha256_acceleration", LAMINATE_SHA256_ACCELERATION);
        record.text("environment.fhe_backend", "seal-bgv");
        record.text("environment.trace_execution", "saved-response-verification");
        record.text("environment.os", client_system.os);
        record.text("environment.cpu", client_system.cpu);
        record.integer("environment.physical_cores", client_system.physical_cores);
        record.integer("environment.logical_cores", client_system.logical_cores);
        record.integer("environment.ram_bytes", client_system.ram_bytes);
        record.text("environment.threading", "single-cpu-process");
        record.integer("environment.worker_threads", 1);
        if (const auto cpu = pinned_logical_cpu()) record.integer("environment.pinned_cpu", *cpu);
        else record.text("environment.pinned_cpu", "not-observed");
        emit_cpu_feature_availability(record, client_system);
        record.text("environment.command", exact_command(argc, argv));
        record.integer("verified.output_count", outputs);
        record.text("verification.result", "PASS");
        record.text("recovery.kind", "saved-response-client-remeasurement-v1");
        record.text("recovery.encryption_scope", "remeasured-with-original-client-keys; discarded-ciphertexts");
        record.text("diagnostic.result", "PASS");
        record.text("diagnostic.scope", "saved-response-client-remeasurement; original benchmark status unchanged");
        result.publish();
        std::cout << "SAVED RESPONSE VERIFICATION PASS\nDiagnostic output: "
                  << command.output_directory << "\nOriginal run remains unchanged.\n";
        return 0;
    } catch (const std::exception &error) {
        const std::string message = "FAILED at " + current_stage + ": " + error.what() + '\n';
        try {
            publish_private_file(command.output_directory / "failure.txt",
                {reinterpret_cast<const std::uint8_t *>(message.data()), message.size()});
        } catch (...) {
            // Reporting failure must not replace the decoding/verifier error.
        }
        throw;
    }
}

int run_process_client(const ProcessCommand &command, int argc,
                       char **argv) {
    Stopwatch process_stopwatch;
    const std::int64_t started = unix_milliseconds();
    require_completed_process_setup(command);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "client" /
                              "activity.jsonl",
                          "client");
    activity.transition("loading_preprocessing");
    LoadedClientProcessInputs loaded = load_client_process_inputs(
        command, [&](std::string_view stage) {
            activity.transition(stage);
        });
    const Timing load_timing = loaded.preprocessing_load_timing;

    activity.transition("encrypting_inputs");
    auto encrypted = timed([&] {
        return payload::prevalidated_input_encryption::
            encrypt_wide_inputs_from_validated_payload<SealBackend>(
                loaded.client.context(), loaded.client.payload(),
                loaded.inputs);
    });
    activity.transition("binding_session");
    auto begun = timed([&] {
        return base_client_detail::
            bind_validated_base_request_session<SealBackend>(
                loaded.client, loaded.inputs,
                std::move(encrypted.first),
                fresh_process_nonce());
    });
    BaseClientRequestStart<SealBackend> started_request =
        std::move(begun.first);

    activity.transition("encoding_request");
    auto encoded = timed([&] {
        return encode_base_request<SealBackend>(
            loaded.client.context(), started_request.request);
    });
    const std::size_t request_bytes_count = encoded.first.size();
    const std::filesystem::path request_path =
        command.run_directory / "shared" / "transcript" /
        "cli-to-srv-request.bin";
    activity.transition("publishing_request");
    const Timing publish_timing = timed_void([&] {
        publish_private_file(request_path, encoded.first);
    });
    const std::int64_t request_published = unix_milliseconds();
    std::cout << "CLIENT REQUEST PUBLISHED\n"
              << "Waiting for exactly one server response at:\n  "
              << (command.run_directory / "shared" / "transcript" /
                  "srv-to-cli-response.bin")
              << "\nThe client will report its idle wait every 60 seconds.\n";
    started_request.request = BaseRequest<SealBackend>{};
    std::vector<std::uint8_t>{}.swap(encoded.first);

    const std::filesystem::path response_path =
        command.run_directory / "shared" / "transcript" /
        "srv-to-cli-response.bin";
    const Timing wait_timing = wait_for_artifact(
        response_path, "client", "server response", activity,
        "waiting_for_server_response",
        command.run_directory / "server" / "failure.txt",
        command.run_directory / "server" / "activity.jsonl");
    activity.transition("reading_response_file");
    auto response_file = timed([&] {
        return read_bounded_file(
            response_path,
            loaded.wire_limits.max_message_bytes);
    });
    const std::size_t response_bytes_count = response_file.first.size();
    activity.transition("decoding_response");
    auto decoded = timed([&] {
        BaseResponse<SealBackend> response =
            decode_base_response<SealBackend>(
                loaded.client, response_file.first,
                loaded.wire_limits,
                TraceProvenance::FheEvaluated);
        return response;
    });
    BaseResponse<SealBackend> response = std::move(decoded.first);
    std::vector<std::uint8_t>().swap(response_file.first);

    verification_profile::VerificationBreakdown verification_components;
    auto transcript = [&] {
        verification_profile::ScopedVerificationSession session(verification_components);
        verification_profile::ScopedVerificationPhase recovery(
            verification_profile::Category::Recovery);
        return Transcript(kProcessTranscriptDomain);
    }();
    activity.transition("opening_response");
    auto opened = timed([&] {
        verification_profile::ScopedVerificationSession session(verification_components);
        return open_base_response<SealBackend>(
            loaded.client, std::move(started_request.state), response,
            transcript);
    });
    if (!opened.first) {
        throw std::runtime_error(
            "client rejected the response before proof verification");
    }
    activity.transition("verifying_proof");
    protocol::BaseVerifierTimings verifier_breakdown;
    auto verified = timed([&] {
        verification_profile::ScopedVerificationSession session(verification_components);
        return verify_opened_base_response_profiled<SealBackend>(
            loaded.client, std::move(*opened.first), response,
            transcript, verifier_breakdown);
    });
    if (!verified.first ||
        verified.first->size() != loaded.client.payload().outputs.size()) {
        std::string reason =
            gkr::base_detail::base_verifier_diagnostic().to_string();
        if (verified.first &&
            verified.first->size() !=
                loaded.client.payload().outputs.size()) {
            reason = "verified output count " +
                     std::to_string(verified.first->size()) +
                     " != expected " +
                     std::to_string(loaded.client.payload().outputs.size());
        }
        throw std::runtime_error("client verification FAILED at " + reason);
    }

    const Timing process_timing = process_stopwatch.stop();
    const std::int64_t finished = unix_milliseconds();
    const SystemInfo client_system = system_info();
    require(client_system.peak_rss_bytes <=
                loaded.stored.client_peak_resident_bytes,
            "observed Base client peak RSS exceeds its setup-bound reserve");
    CompletedResultReport report(command.run_directory / "client" /
                                 "result.txt");
    const Record record(report.mirror());
    record.text("format", "laminate-benchmark-client-v2");
    emit_process_identity(record, command, loaded.stored);
    emit_process_geometry(record, loaded);
    record.integer("timing.client.started_unix_ms", started);
    record.integer("timing.client.request_published_unix_ms",
                   request_published);
    record.integer("timing.client.finished_unix_ms", finished);
    emit_timing_pair(record, "timing.client.load_preprocessing",
                     load_timing);
    emit_timing_pair(record, "timing.client.encrypt_inputs",
                     encrypted.second);
    emit_timing_pair(record, "timing.client.bind_session", begun.second);
    emit_timing_pair(record, "timing.client.encode_request",
                     encoded.second);
    emit_timing_pair(record, "timing.client.publish_request",
                     publish_timing);
    emit_timing_pair(record, "timing.client.wait_for_response",
                     wait_timing);
    emit_timing_pair(record, "timing.client.read_response_file",
                     response_file.second);
    emit_timing_pair(record, "timing.client.decode_response",
                     decoded.second);
    emit_timing_pair(record, "timing.client.open_response",
                     opened.second);
    emit_timing_pair(record, "timing.client.verify", verified.second);
    emit_timing_pair(
        record, "timing.client.verify.decryption_and_unpack",
        Timing{verifier_breakdown.packed_message_verification_wall_ms,
               verifier_breakdown.packed_message_verification_cpu_ms});
    emit_timing_pair(
        record, "timing.client.verify.gate_mle_opening",
        Timing{verifier_breakdown.gate_mle_opening_wall_ms,
               verifier_breakdown.gate_mle_opening_cpu_ms});
    record.integer("timing.client.verify.layer_count",
                   verifier_breakdown.layers.size());
    for (std::size_t index = 0;
         index < verifier_breakdown.layers.size(); ++index) {
        const protocol::BaseLayerTiming &layer =
            verifier_breakdown.layers[index];
        const std::string prefix =
            "timing.client.verify.layer." + std::to_string(index);
        record.integer(prefix + ".circuit_layer", layer.layer);
        record.text(prefix + ".kind",
                    layer.kind == payload::LayerKind::Affine
                        ? "affine"
                        : "multiplication");
        emit_timing_pair(record, prefix,
                         Timing{layer.wall_ms, layer.cpu_ms});
    }
    const Timing per_request_timing = emit_client_computation(
        record, encrypted.second, verification_components);
    emit_timing_pair(record, "timing.client.per_request_total",
                     per_request_timing);
    // Both fields report the same per-request computation total.
    emit_timing_pair(record, "timing.client.online_total",
                     per_request_timing);
    record.text("timing.client.per_request_total.scope",
                std::string(kClientComputationScope));
    record.text("timing.client.online_total.scope",
                "alias-of-client-per-request-total");
    emit_timing_pair(record, "timing.client.process_total", process_timing);
    record.integer("wire.request_bytes", request_bytes_count);
    record.integer("wire.response_bytes", response_bytes_count);
    record.integer("memory.client.admitted_peak_resident_bytes",
                   loaded.stored.client_peak_resident_bytes);
    record.integer("memory.client.peak_rss_bytes",
                   client_system.peak_rss_bytes);
    record.text("environment.command", exact_command(argc, argv));
    record.text("verification.result", "PASS");
    report.publish();
    activity.mark_complete();
    std::cout << "\nCLIENT VERIFICATION PASS\n"
              << "The response is accepted. Generate the human report with:\n"
              << "  benches/run_gcp.sh summary base " << command.profile
              << ' ' << command.run_directory << '\n';
    return 0;
}

void emit_proof_sizes(
    const Record &record, std::size_t response_bytes,
    const base_wire_detail::ProofTransportSizeBreakdown &transport,
    const protocol::BaseProofSizeBreakdown &canonical) {
    const std::size_t envelope_header = kBaseDelegationWireHeaderBytes;
    const std::size_t public_bindings = 4U * Digest{}.size();
    const std::size_t inner_length_prefix = sizeof(std::uint64_t);
    if (response_bytes < envelope_header + public_bindings +
                             inner_length_prefix + transport.total_bytes) {
        throw std::logic_error(
            "Base response is smaller than its canonical components");
    }
    const std::size_t output_statement =
        response_bytes - envelope_header - public_bindings -
        inner_length_prefix - transport.total_bytes;
    record.integer("proof.response.total_bytes", response_bytes);
    record.integer("proof.response.envelope_header_bytes", envelope_header);
    record.integer("proof.response.public_bindings_bytes", public_bindings);
    record.integer("proof.response.output_statement_bytes",
                   output_statement);
    record.integer("proof.response.inner_length_prefix_bytes",
                   inner_length_prefix);
    record.integer("proof.response.inner_transport_bytes",
                   transport.total_bytes);
    record.integer("proof.response.framing_bytes",
                   response_bytes - transport.total_bytes);
    record.integer("proof.response.duplicated_output_claim_bytes", 0);

    record.integer("proof.transport.total_bytes", transport.total_bytes);
    record.integer("proof.transport.statement_and_metadata_bytes",
                   transport.statement_and_metadata_bytes);
    record.integer("proof.transport.round_message_bytes",
                   transport.round_message_bytes);
    record.integer("proof.transport.terminal_message_bytes",
                   transport.terminal_message_bytes);
    record.integer("proof.transport.partial_gate_mle_bytes",
                   transport.partial_gate_mle_bytes);
    record.integer("proof.transport.gate_mle_opening_bytes",
                   transport.gate_mle_opening_bytes);
    record.integer("proof.transport.logical_round_messages",
                   transport.logical_round_messages);
    record.integer("proof.transport.extension_ciphertexts",
                   transport.extension_ciphertexts);
    record.integer("proof.transport.base_ciphertexts",
                   transport.base_ciphertexts);
    record.integer("proof.transport.public_plaintext_coefficients",
                   transport.public_plaintext_coefficients);
    record.integer("proof.transport.public_plaintext_field_elements",
                   transport.public_plaintext_field_elements);

    record.integer("proof.canonical.total_bytes", canonical.total_bytes);
    record.integer("proof.canonical.statement_and_metadata_bytes",
                   canonical.statement_and_metadata_bytes);
    record.integer("proof.canonical.round_message_bytes",
                   canonical.round_message_bytes);
    record.integer("proof.canonical.terminal_message_bytes",
                   canonical.terminal_message_bytes);
    record.integer("proof.canonical.partial_gate_mle_bytes",
                   canonical.partial_gate_mle_bytes);
    record.integer("proof.canonical.gate_mle_opening_bytes",
                   canonical.gate_mle_opening_bytes);
}

void emit_replay_source_io(
    const Record &record, std::string_view phase,
    const payload::PayloadCheckpointReplayIoReport &report) {
    const std::string prefix =
        "work.replay." + std::string(phase) + ".";
    record.text(prefix + "storage.artifact_integrity",
                "same-process-inode-bound-nonreopenable");
    const auto timing = [&](std::string_view name,
                            const payload::FileTraceStoreOperationTiming &value) {
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

std::uint64_t peak_gkr_scratch_bytes(
    const gkr::base_detail::FileBaseGkrReport &report) {
    std::uint64_t peak = 0;
    for (const auto &reduction : report.reductions) {
        if (!reduction.multiplication_artifact) {
            continue;
        }
        peak = std::max(
            peak,
            std::max(
                reduction.multiplication_artifact->storage.physical_bytes,
                reduction.multiplication_artifact->build
                    .external_sort_peak_combined_artifact_bytes));
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

GkrSortDiagnostics gkr_sort_diagnostics(
    const gkr::base_detail::FileBaseGkrReport &report) {
    GkrSortDiagnostics result;
    for (const auto &reduction : report.reductions) {
        if (!reduction.multiplication_artifact) {
            continue;
        }
        const auto &statistics =
            reduction.multiplication_artifact->build;
        ++result.artifacts;
        result.initial_runs = checked_add_u64(
            result.initial_runs, statistics.external_sort_initial_runs,
            "GKR external-sort initial runs");
        result.runs_created = checked_add_u64(
            result.runs_created, statistics.external_sort_runs_created,
            "GKR external-sort runs created");
        result.merge_passes = checked_add_u64(
            result.merge_passes, statistics.external_sort_merge_passes,
            "GKR external-sort merge passes");
        result.maximum_open_runs = std::max<std::uint64_t>(
            result.maximum_open_runs,
            statistics.external_sort_maximum_open_runs);
        result.temporary_bytes_written = checked_add_u64(
            result.temporary_bytes_written,
            statistics.external_sort_temporary_bytes_written,
            "GKR external-sort temporary bytes");
        result.peak_buffered_payload_bytes = std::max(
            result.peak_buffered_payload_bytes,
            statistics.external_sort_peak_buffered_payload_bytes);
        result.retained_temporary_bytes = checked_add_u64(
            result.retained_temporary_bytes,
            statistics.external_sort_retained_temporary_bytes,
            "GKR retained external-sort bytes");
    }
    return result;
}

int run_process_server(const ProcessCommand &command, int argc,
                       char **argv) {
    Stopwatch process_stopwatch;
    const std::int64_t started = unix_milliseconds();
    require_completed_process_setup(command);
    RunLifecycleLock lifecycle(command.run_directory,
                               RunLifecycleLockMode::Shared);
    RoleActivity activity(command.run_directory / "server" /
                              "activity.jsonl",
                          "server");
    const std::filesystem::path request_path =
        command.run_directory / "shared" / "transcript" /
        "cli-to-srv-request.bin";
    const Timing wait_timing = wait_for_artifact(
        request_path, "server", "client request", activity,
        "waiting_for_client_request",
        command.run_directory / "client" / "failure.txt",
        command.run_directory / "client" / "activity.jsonl");
    const std::int64_t request_observed = unix_milliseconds();

    // The server deliberately does no preprocessing work until the complete
    // request artifact exists. This keeps server online accounting behind the
    // request boundary and avoids loading evaluation state for an abandoned
    // client request.
    activity.transition("restoring_execution_plan");
    auto loaded_timed = timed([&] {
        LoadedProcessInputs loaded = load_process_inputs(
            command, [&](std::string_view stage) {
                activity.transition(stage);
            });
        activity.transition("checking_server_capacity");
        (void)require_diagnostic_host(
            loaded.options, loaded.preflight,
            DiagnosticHostAdmissionPoint::ServerStart);
        activity.transition("reading_server_preprocessing");
        std::vector<std::uint8_t> bytes = load_role_preprocessing(
            command.run_directory / "server" / "preprocessing" /
                "server.bin",
            loaded.stored.server_bytes, loaded.stored.server_digest);
        activity.transition("deserializing_server_preprocessing");
        SealBackend::EvalContext context =
            SealBackend::deserialize_evaluation_context_bundle(bytes);
        activity.transition("opening_persisted_gate_mle");
        std::shared_ptr<const gates::GateTableProverKey> gate_mle_key =
            restore_gate_mle_prover_key(
                loaded.circuit, loaded.preflight.public_setup,
                gates::GateTableBuildOptions{
                    .wide_scratch_parent = command.run_directory / "server" / "gate-mle-scratch",
                    .wide_max_disk_bytes = loaded.options.diagnostic.max_live_disk_bytes,
                    .wide_resources = {.min_free_bytes = loaded.options.diagnostic.min_free_disk_bytes},
                    .prover_key_directory = command.run_directory / "server" / "preprocessing" / "gate-mle"});
        activity.transition("constructing_server_context");
        EvaluationSetup<SealBackend> server =
            make_evaluation_setup<SealBackend>(
                loaded.preflight.public_setup, std::move(context),
                std::move(gate_mle_key));
        return std::pair{std::move(loaded), std::move(server)};
    });
    auto [loaded, server] = std::move(loaded_timed.first);
    const Timing load_timing = loaded_timed.second;

    activity.transition("reading_request");
    auto decoded = timed([&] {
        std::vector<std::uint8_t> request_bytes = read_bounded_file(
            request_path,
            loaded.preflight.wire_limits.max_message_bytes);
        const std::size_t size = request_bytes.size();
        BaseRequest<SealBackend> request = decode_base_request<SealBackend>(
            server.context, request_bytes,
            loaded.preflight.wire_limits);
        return std::pair{std::move(request), size};
    });
    BaseRequest<SealBackend> request = std::move(decoded.first.first);
    const std::size_t request_bytes_count = decoded.first.second;

    SessionDirectory session(
        command.run_directory / "server" / "work", false);
    ProgressRecorder progress(command.run_directory / "server" /
                              "progress.jsonl");
    const RuntimeProgressCallback recorder_callback = progress.callback();
    bool payload_evaluation_started = false;
    const RuntimeProgressCallback progress_callback =
        [&](const RuntimeProgressEvent &event) {
            if (!payload_evaluation_started &&
                event.boundary == RuntimeProgressBoundary::Begin) {
                activity.transition("payload_evaluation");
                progress.end_phase("server_payload_execution_preflight");
                progress.begin_phase("server_payload_evaluation");
                payload_evaluation_started = true;
            }
            recorder_callback(event);
        };
    const std::filesystem::path replay_directory =
        session.make_child("payload-replay");
    auto proof_options = make_proof_options(
        loaded.circuit, session,
        loaded.preflight.multiplication_scratch_limits,
        loaded.preflight.multiplication_sort_buffer_payload_bytes);
    proof_options.progress = progress_callback;

    SealBackend::reset_counts(server.context);
    SealBackend::set_counting(server.context, true);
    activity.transition("payload_execution_preflight");
    progress.begin_phase("server_payload_execution_preflight");
    auto evaluated = timed([&] {
        return evaluate_base_request<
            SealBackend>(
            loaded.profile.payload, loaded.circuit, server, request,
            loaded.preflight.certified_schedule,
            loaded.preflight.replay_problem,
            loaded.preflight.replay_budgets,
            loaded.preflight.replay_plan,
            PayloadCheckpointReplayExecutionOptions{
                .directory = replay_directory,
                .min_free_bytes =
                    loaded.options.diagnostic.min_free_disk_bytes,
                .max_checkpoint_metadata_bytes = 4096,
                .lifecycle =
                    FileTraceSessionLifecycle::IrreversibleNoRetry,
                .progress = progress_callback},
            std::move(proof_options), loaded.preflight.capacity_caps,
            loaded.preflight.capacity_components);
    });
    if (payload_evaluation_started) {
        progress.end_phase("server_payload_evaluation");
    } else {
        progress.end_phase("server_payload_execution_preflight");
    }
    SealBackend::set_counting(server.context, false);
    const SealBackend::OperationCounts evaluation_counts =
        SealBackend::counts(server.context);
    require(evaluation_counts.calls(SealBackend::OperationKind::Encrypt) ==
                0,
            "server payload evaluation encrypted a new ciphertext");
    require(evaluation_counts.calls(SealBackend::OperationKind::Sub) == 0,
            "server payload evaluation constructed zero by subtraction");
    request = BaseRequest<SealBackend>{};

    Transcript transcript(kProcessTranscriptDomain);
    SealBackend::reset_counts(server.context);
    SealBackend::set_counting(server.context, true);
    activity.transition("gkr_proving");
    progress.begin_phase("server_gkr_proving");
    auto proved = timed([&] {
        return prove_base_response_irreversible<
            SealBackend>(loaded.profile.payload, loaded.circuit, server,
                         evaluated.first, transcript);
    });
    progress.end_phase("server_gkr_proving");
    SealBackend::set_counting(server.context, false);
    const SealBackend::OperationCounts proving_counts =
        SealBackend::counts(server.context);
    require(proved.first.payload_replay_report
                .all_payload_artifacts_retired &&
                proved.first.payload_replay_report.live_physical_bytes == 0,
            "irreversible Base proof retained payload artifacts");

    base_wire_detail::ProofTransportSizeBreakdown proof_transport;
    activity.transition("encoding_response");
    auto encoded = timed([&] {
        return encode_base_response<SealBackend>(
            server.context, proved.first.response, &proof_transport);
    });
    const std::size_t response_bytes_count = encoded.first.size();
    const protocol::BaseProofSizeBreakdown canonical_proof_size =
        protocol::measure_proof_size(proved.first.response.proof);
    const std::filesystem::path response_path =
        command.run_directory / "shared" / "transcript" /
        "srv-to-cli-response.bin";
    activity.transition("publishing_response");
    const Timing publish_timing = timed_void([&] {
        publish_private_file(response_path, encoded.first);
    });

    const Timing online_timing = add_timings(
        {load_timing, decoded.second, evaluated.second, proved.second,
         encoded.second, publish_timing});
    const Timing process_timing = process_stopwatch.stop();
    const std::int64_t finished = unix_milliseconds();
    const SystemInfo server_system = system_info();
    require(server_system.peak_rss_bytes <=
                loaded.preflight.capacity_caps.max_resident_ram_bytes,
            "observed Base server peak RSS exceeds its setup-bound cap");
    CompletedResultReport report(command.run_directory / "server" /
                                 "result.txt");
    const Record record(report.mirror());
    record.text("format", "laminate-benchmark-server-v1");
    emit_process_identity(record, command, loaded.stored);
    emit_process_geometry(record, loaded);
    record.integer("timing.server.started_unix_ms", started);
    record.integer("timing.server.request_observed_unix_ms",
                   request_observed);
    record.integer("timing.server.finished_unix_ms", finished);
    emit_timing_pair(record, "timing.server.load_preprocessing",
                     load_timing);
    emit_timing_pair(record, "timing.server.wait_for_request", wait_timing);
    emit_timing_pair(record, "timing.server.read_request", decoded.second);
    emit_timing_pair(record, "timing.server.payload_evaluation",
                     evaluated.second);
    emit_timing_pair(record, "timing.server.gkr_proving", proved.second);
    emit_timing_pair(record, "timing.server.encode_response",
                     encoded.second);
    emit_timing_pair(record, "timing.server.publish_response",
                     publish_timing);
    emit_timing_pair(record, "timing.server.online_total", online_timing);
    record.text(
        "timing.server.online_total.scope",
        "cold-preprocessing-load-request-codec-payload-evaluation-gkr-"
        "proving-response-codec-and-publication;excludes-peer-idle-wait");
    emit_timing_pair(record, "timing.server.process_total", process_timing);
    emit_seal_operation_counts(record, "server_payload_evaluation",
                               evaluation_counts);
    emit_seal_operation_counts(record, "server_gkr_proving",
                               proving_counts);
    record.integer("wire.request_bytes", request_bytes_count);
    record.integer("wire.response_bytes", response_bytes_count);
    record.integer("wire.proof_response_bytes", response_bytes_count);
    emit_proof_sizes(record, response_bytes_count, proof_transport,
                     canonical_proof_size);
    record.integer(
        "storage.payload_replay_peak_live_physical_bytes",
        proved.first.payload_replay_report.peak_live_physical_bytes);
    record.integer(
        "storage.payload_replay_peak_live_scratch_bytes",
        proved.first.payload_replay_report.peak_live_scratch_bytes);
    record.integer(
        "storage.payload_replay_total_reclaimed_physical_bytes",
        proved.first.payload_replay_report.total_reclaimed_physical_bytes);
    emit_replay_source_io(
        record, "forward", proved.first.payload_replay_report.forward);
    emit_replay_source_io(
        record, "reverse", proved.first.payload_replay_report.reverse_replay);
    emit_replay_source_io(
        record, "gkr_source",
        proved.first.payload_replay_report.gkr_source_reads);
    record.integer("storage.gkr_peak_live_scratch_bytes",
                   peak_gkr_scratch_bytes(proved.first.gkr_report));
    const GkrSortDiagnostics gkr_sort =
        gkr_sort_diagnostics(proved.first.gkr_report);
    record.integer("work.gkr.multiplication_sort.artifacts",
                   gkr_sort.artifacts);
    record.integer("work.gkr.multiplication_sort.initial_runs",
                   gkr_sort.initial_runs);
    record.integer("work.gkr.multiplication_sort.runs_created",
                   gkr_sort.runs_created);
    record.integer("work.gkr.multiplication_sort.merge_passes",
                   gkr_sort.merge_passes);
    record.integer("work.gkr.multiplication_sort.maximum_open_runs",
                   gkr_sort.maximum_open_runs);
    record.integer("storage.gkr_multiplication_sort_temporary_bytes_written",
                   gkr_sort.temporary_bytes_written);
    record.integer(
        "memory.gkr_multiplication_sort_peak_buffered_payload_bytes",
        gkr_sort.peak_buffered_payload_bytes);
    record.integer("storage.gkr_multiplication_sort_retained_temporary_bytes",
                   gkr_sort.retained_temporary_bytes);
    record.integer("memory.server.admitted_peak_resident_bytes",
                   loaded.preflight.capacity_admission.max_resident_ram_bytes);
    record.integer(
        "memory.multiplication_sort_buffer_limit_bytes",
        loaded.preflight.multiplication_sort_buffer_payload_bytes);
    record.integer("memory.client.admitted_peak_resident_bytes",
                   loaded.stored.client_peak_resident_bytes);
    record.integer("memory.concurrent.admitted_peak_resident_bytes",
                   checked_add_u64(
                       loaded.preflight.capacity_admission
                           .max_resident_ram_bytes,
                       loaded.stored.client_peak_resident_bytes,
                       "reported Base concurrent resident peak"));
    record.integer("memory.server.peak_rss_bytes",
                   server_system.peak_rss_bytes);
    record.text("environment.command", exact_command(argc, argv));
    progress.emit(record);
    record.text("server.result", "PASS");
    report.publish();
    progress.mark_server_complete();
    activity.mark_complete();
    std::cout << "\nSERVER RESPONSE PUBLISHED\n"
              << "Server work is complete, but the run is not accepted "
                 "until the client reports verification PASS.\n";
    return 0;
}

#ifdef LAMINATE_BASE_CAPACITY_TEST
void check_planned_gate_wire_budget(
    const LayeredCircuit &circuit, const GateMlePreprocessingPlan &plan,
    const DirectBaseWireRequirements &wire) {
    // Supply only planned geometry and a nonzero placeholder root. This test
    // exercises the actual process limit derivation and codec without
    // producing any target commitment, ciphertext, or proof.
    basefold::Digest placeholder_root{};
    placeholder_root.fill(1);
    gates::GateTableVerifierKey key;
    key.layout = plan.layout;
    key.basefold_parameters = plan.basefold_parameters;
    key.foldable_parameters = plan.foldable_parameters;
    key.wide_public_commitment = basefold::foldable::Metadata{
        .root = placeholder_root, .m = plan.wide_public_message_size,
        .width = plan.wide_public_width};
    std::vector<std::size_t> offsets(plan.tables.size());
    for (const auto &block : gates::make_wide_public_blocks(plan.layout))
        offsets[block.selector] = block.offset;
    for (std::size_t selector = 0; selector < plan.tables.size(); ++selector) {
        const auto &shape = plan.tables[selector];
        key.tables.push_back({
            .message_size = shape.message_size,
            .shard_size = shape.shard_size,
            .shard_count = shape.shard_count,
            .logical_width = shape.logical_width,
            .physical_width = shape.physical_width,
            .root = placeholder_root,
            .wide_block_offset = offsets[selector]});
    }
    const auto limits = diagnostic_wire_limits(wire, circuit, key);
    require(limits.max_gate_target_values <= (std::size_t{1} << 24U),
            "target GateMLE target-value cap exceeds the setup codec hard cap");
    const auto requests = 24U *
        std::max<std::size_t>(1, plan.layout.wide_layers.size());
    std::size_t legacy_maximum_table_width = 0;
    for (const auto &table : key.tables) {
        legacy_maximum_table_width =
            std::max(legacy_maximum_table_width, table.physical_width);
        const auto local_values = checked_multiply_u64(
            requests, table.physical_width, "planned local target values");
        const auto shared_rows = checked_multiply_u64(
            requests, gates::wide_public_operands_per_request(
                table, *key.wide_public_commitment),
            "planned public target rows");
        const auto shared_values = checked_multiply_u64(
            shared_rows, key.wide_public_commitment->width,
            "planned public target values");
        require(checked_add_u64(local_values, shared_values,
                               "planned total target values") <=
                    limits.max_gate_target_values,
                "target GateMLE cap omits a decoded target matrix");
    }
    require(limits.max_gate_target_values > checked_multiply_u64(
                requests, legacy_maximum_table_width, "legacy target-value cap"),
            "target GateMLE cap did not include the shared public target matrix");
    ProcessWriter writer;
    encode_process_wire_limits(writer, limits);
    const auto encoded = std::move(writer).finish();
    ProcessReader reader(encoded);
    require(decode_process_wire_limits(reader) == limits,
            "target GateMLE limits do not round trip through setup.bin");
    std::cout << "GateMLE target-value decode cap=" << limits.max_gate_target_values
              << " (shared public width=" << plan.wide_public_width << ")\n";
}

int run_setup_capacity_test(std::string_view profile_name) {
    const auto root = std::filesystem::temp_directory_path() /
        ("laminate-base-resource-plan-" + std::string(profile_name));
    require(!std::filesystem::exists(root), "capacity-test path already exists");
    const ProcessCommand command{
        .action = ProcessAction::Setup,
        .variant = "base",
        .profile = std::string(profile_name),
        .run_directory = root};
    const auto selected = process_profile(profile_name);
    const auto host = derive_host_resource_budget(
        8'500'000'000'000ULL, 372'000'000'000ULL);
    const auto options = process_options(command, selected, host);
    const auto profile = make_run_profile(options, false);
    require(process_client_seal_parameters(selected, options) ==
                profile.seal_parameters,
            "client parameter reload differs from the actual profile parameters");
    const auto circuit = compile(profile.payload);
    const auto schedule = derive_certified_uniform_honest_base_proof_schedule(
        circuit, profile.seal_parameters.exact_data_primes,
        profile.calibration, selected.proof_ingress_rns_limbs);
    const auto gate_plan = plan_gate_mle_preprocessing(
        circuit, gates::GateTableSet::Wide,
        {.wide_scratch_parent = root / "gate-mle-scratch",
         .wide_max_disk_bytes = options.diagnostic.max_live_disk_bytes});
    require(schedule.schedule().payload_model_accepts(),
            "fixed profile failed dependency-aware payload noise admission");
    const auto &output_noise = schedule.schedule().layers_in_evaluation_order.back();
    const auto doubled_phase_bits = NaturalMagnitude::multiply(
        output_noise.evaluated_phase_bound, 2U).bit_count();
    const auto output_modulus_bits = NaturalMagnitude::product(
        std::span(profile.seal_parameters.exact_data_primes).first(
            output_noise.input_rns_limb_count)).bit_count();
    if (profile_name != "quick") {
        const auto payload_drops = std::count_if(
            schedule.schedule().layers_in_evaluation_order.begin(),
            schedule.schedule().layers_in_evaluation_order.end(),
            [](const auto &layer) { return layer.switched(); });
        require(payload_drops == 8, "target must retain room for all eight payload drops");
    }
    if (profile_name == "target-mulHeavyPyramid") {
        require(doubled_phase_bits < output_modulus_bits && output_modulus_bits == 130 &&
                    output_noise.input_rns_limb_count == 3 &&
                    profile.seal_parameters.exact_data_primes.size() == 11,
                "pyramid noise regression changed its bound or fixed modulus profile");
    }
    const auto plan = finish_diagnostic_preflight(
        options, profile, circuit, schedule, std::nullopt, gate_plan.resources);
    check_planned_gate_wire_budget(circuit, gate_plan, plan.wire);
    require(plan.replay_plan.selected.feasible(), "target replay is infeasible");
    require(plan.capacity_admission.max_resident_ram_bytes <=
                plan.capacity_caps.max_resident_ram_bytes,
            "target resident admission exceeds cap");
    require(plan.setup_start_available_disk_bytes <=
                host.observed_available_disk_bytes,
            "target setup disk admission exceeds host");
    require(!plan.public_setup.outsourced_gate_mle,
            "resource planner unexpectedly built a commitment");
    require(!std::filesystem::exists(root), "resource planner wrote files");
    auto constrained = options;
    constrained.host_budget = derive_host_resource_budget(
        host.observed_available_disk_bytes,
        kBenchmarkHostRamSafetyReserveBytes + 1U);
    bool rejected = false;
    try {
        (void)finish_diagnostic_preflight(
            constrained, profile, circuit, schedule, std::nullopt,
            gate_plan.resources);
    } catch (const std::invalid_argument &) {
        rejected = true;
    }
    require(rejected, "insufficient RAM was not rejected before preprocessing");
    require(!std::filesystem::exists(root), "failed preflight wrote files");
    std::cout << profile_name << ": capacity preflight PASS; server cap="
              << plan.capacity_caps.max_resident_ram_bytes
              << " bytes, sort payload="
              << plan.multiplication_sort_buffer_payload_bytes << " bytes; final doubled phase bound="
              << doubled_phase_bits << " bits, active modulus="
              << output_modulus_bits << " bits; modeled switch events="
              << schedule.schedule().modeled_switch_events << "; rounding allowance="
              << schedule.schedule().calibration.switch_rounding_error_bound << '\n';
    return 0;
}
#endif

} // namespace

int main(int argc, char **argv) {
    laminate::bench::configure_process_memory_runtime();
    try {
#ifdef LAMINATE_BASE_CAPACITY_TEST
        if (argc != 2) throw std::invalid_argument("expected a capacity-test profile");
        return run_setup_capacity_test(argv[1]);
#endif
        if (argc == 2 &&
            std::string_view(argv[1]) == "build_info") {
            return run_build_info();
        }
        if (argc > 1 && is_process_action(argv[1])) {
            const ProcessCommand command =
                parse_process_command(argc, argv);
            bool created_setup_run = false;
            try {
                switch (command.action) {
                case ProcessAction::Setup:
                    return run_process_setup(command, argc, argv, created_setup_run);
                case ProcessAction::RunClient:
                    return run_process_client(command, argc, argv);
                case ProcessAction::RunServer:
                    return run_process_server(command, argc, argv);
                case ProcessAction::Status:
                    return run_process_status(command);
                case ProcessAction::VerifySavedResponse:
                    return run_saved_response_verification(command, argc, argv);
                }
                throw std::logic_error("unknown process action");
            } catch (const std::exception &error) {
                // A rejected setup/recovery must never write failure evidence
                // into a pre-existing destination, especially its source run.
                if (command.action != ProcessAction::VerifySavedResponse &&
                    (command.action != ProcessAction::Setup || created_setup_run)) {
                    publish_process_failure(command, error.what());
                }
                throw;
            }
        }
        throw std::invalid_argument(
            "use build_info or ACTION --variant base --profile "
            "quick|target-balancedLaned|target-mulHeavyPyramid --run-dir "
            "ABSOLUTE_PATH; see "
            "docs/GCP_BENCHMARKS.md");
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
