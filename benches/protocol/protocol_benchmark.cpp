/// @file protocol_benchmark.cpp
/// @brief Reproducible Base/Folded/Laned protocol benchmark.

#include "protocol_git_state.hpp"

#include "benchmark_support.hpp"
#include "completed_result_report.hpp"
#include "gate_mle_benchmark.hpp"
#include "protocol_progress.hpp"

#include "laminate/protocol/fiat_shamir.hpp"
#include "laminate/protocol/detail/packing/gkr_transcript_replay.hpp"
#include "laminate/bench/schedule_cost.hpp"
#include "laminate/delegation/packed/statement.hpp"
#include "laminate/fhe/mock_backend.hpp"
#ifdef LAMINATE_WITH_SEAL
#include "laminate/fhe/seal_backend.hpp"
#endif
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/evaluator.hpp"
#include "laminate/payload/laned_fhe_evaluator.hpp"
#include "laminate/payload/trace/fhe_trace_id.hpp"
#include "laminate/payload/input_encryption.hpp"
#include "laminate/payload/trace/trace_sink.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/wide_fhe_evaluator.hpp"
#include "laminate/payload/fixtures/workloads.hpp"
#include "laminate/protocol/base.hpp"
#include "laminate/protocol/folded.hpp"
#include "laminate/protocol/laned.hpp"
#include "laminate/protocol/packed/wire/proof.hpp"
#include "laminate/protocol/metrics/profiling.hpp"
#include "laminate/protocol/metrics/proof_size.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

enum class BackendKind { Mock, Seal };
enum class ProtocolKind { Base, Folded, Laned };

PackedProtocolVariant packed_variant(ProtocolKind kind) {
    switch (kind) {
    case ProtocolKind::Folded:
        return PackedProtocolVariant::Folded;
    case ProtocolKind::Laned:
        return PackedProtocolVariant::Laned;
    case ProtocolKind::Base:
        break;
    }
    throw std::invalid_argument("Base has no packed protocol variant");
}

Digest benchmark_packed_session_id(
    ProtocolKind kind, const Digest &setup_id, const Digest &circuit_id,
    const Digest &trace_id, std::uint64_t seed) {
    Sha256Hasher hasher;
    static constexpr std::string_view domain =
        "LaminateImpl/PackedBenchmarkSession/v1";
    hasher.update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(domain.data()),
        domain.size()));
    const std::uint8_t encoded_variant =
        static_cast<std::uint8_t>(packed_variant(kind));
    hasher.update(std::span<const std::uint8_t>(&encoded_variant, 1));
    hasher.update(setup_id);
    hasher.update(circuit_id);
    hasher.update(trace_id);
    std::uint8_t encoded_seed[8]{};
    for (std::size_t byte = 0; byte < sizeof(encoded_seed); ++byte) {
        encoded_seed[byte] = static_cast<std::uint8_t>(
            (seed >> (8U * byte)) & std::uint64_t{0xff});
    }
    hasher.update(encoded_seed);
    return hasher.finish();
}

constexpr std::size_t kPackedOutputCanonicalErrorBits = 10;

struct Options {
    std::filesystem::path result_file;
    std::filesystem::path progress_file;
    BackendKind backend = BackendKind::Mock;
    ProtocolKind protocol = ProtocolKind::Base;
    GateMleBenchmarkProfile gate_mle = GateMleBenchmarkProfile::Direct;
    WorkloadKind workload = WorkloadKind::Diamond;
    std::size_t slots = 8;
    std::size_t lanes = 0;
    std::size_t depth = 2;
    std::size_t width = 2;
    std::uint64_t seed = 1;
    std::size_t iterations = 1;
    std::size_t required_proof_depth = 4;
    std::size_t packing_repetitions =
        kPackingWellFormednessRepetitions;
    std::size_t fresh_rns_limbs = 5;
    std::size_t bits_per_limb = 60;
    std::vector<int> data_prime_bit_sizes;
    std::vector<std::uint64_t> exact_data_primes;
    std::size_t special_prime_bits = 60;
    std::uint64_t exact_special_prime = 0;
    std::size_t initial_noise_margin_bits = 20;
    std::size_t rotation_noise_bits = 1;
    std::size_t relinearization_noise_bits = 2;
    std::size_t gate_table_max_entries = std::size_t{1} << 22;
    std::size_t max_ciphertext_modulus_bits = 0;
    std::size_t max_key_modulus_bits = 0;
    std::string security = "none";
    std::string run_tier = "unit";
    std::string modulus_chain_profile =
        "uniform-head-width-benchmark-fixture";
};

BackendKind parse_backend(std::string_view name) {
    if (name == "mock") {
        return BackendKind::Mock;
    }
    if (name == "seal-bgv") {
        return BackendKind::Seal;
    }
    throw std::invalid_argument("unknown backend: " + std::string(name));
}

ProtocolKind parse_protocol(std::string_view name) {
    if (name == "base") {
        return ProtocolKind::Base;
    }
    if (name == "folded") {
        return ProtocolKind::Folded;
    }
    if (name == "laned") {
        return ProtocolKind::Laned;
    }
    throw std::invalid_argument("unknown protocol: " + std::string(name));
}

WorkloadKind parse_workload(std::string_view name) {
    if (name == "diamond") {
        return WorkloadKind::Diamond;
    }
    if (name == "deep-snake") {
        return WorkloadKind::DeepSnake;
    }
    if (name == "fanout" || name == "fanout-heavy") {
        return WorkloadKind::FanoutHeavy;
    }
    if (name == "wide-rotate" || name == "rotation-heavy") {
        return WorkloadKind::RotationHeavy;
    }
    throw std::invalid_argument("unknown workload: " + std::string(name));
}

std::vector<int> parse_bit_sizes(std::string_view value,
                                 std::string_view option) {
    std::vector<int> result;
    while (!value.empty()) {
        const std::size_t comma = value.find(',');
        const std::size_t bits = parse_size(value.substr(0, comma), option);
        if (bits > static_cast<std::size_t>(
                       std::numeric_limits<int>::max())) {
            throw std::invalid_argument(std::string(option) +
                                        " entry is too large");
        }
        result.push_back(static_cast<int>(bits));
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return result;
}

std::vector<std::uint64_t> parse_primes(std::string_view value,
                                        std::string_view option) {
    std::vector<std::uint64_t> result;
    while (!value.empty()) {
        const std::size_t comma = value.find(',');
        result.push_back(static_cast<std::uint64_t>(
            parse_size(value.substr(0, comma), option)));
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return result;
}

std::size_t packed_candidate_limb_count(std::size_t proof_ingress_depth,
                                        std::size_t payload_depth) {
    if (proof_ingress_depth >
        std::numeric_limits<std::size_t>::max() - payload_depth) {
        throw std::invalid_argument(
            "proof-ingress depth plus payload depth overflows the RNS "
            "limb count");
    }
    return proof_ingress_depth + payload_depth;
}

std::vector<int> packed_candidate_limb_widths(std::size_t count) {
    if (count == 0) {
        return {};
    }
    // q0 is the native 60-bit proof field. q1 and q2 reserve headroom for
    // transcript packing. Smaller payload limbs limit the scale lost at
    // each modulus switch. These are diagnostic noise parameters.
    static constexpr std::array<int, 10> prefix{
        60, 48, 48, 37, 37, 37, 37, 38, 38, 39};
    std::vector<int> result(count, 40);
    std::copy_n(prefix.begin(), std::min(count, prefix.size()),
                result.begin());
    return result;
}

void print_usage(std::ostream &output) {
    output
        << "Usage: laminate_protocol_bench [options]\n"
        << "  --backend mock|seal-bgv\n"
        << "  --protocol base|folded|laned\n"
        << "  --gate-mle direct|outsourced-basefold\n"
        << "  --workload diamond|deep-snake|fanout-heavy|rotation-heavy\n"
        << "  --slots N                 SIMD slots / polynomial degree\n"
        << "  --lanes B                 independent lanes (Laned only)\n"
        << "  --depth d                 payload multiplicative depth\n"
        << "  --width W                 workload parallelism/fanout\n"
        << "  --seed S                  deterministic workload seed\n"
        << "  --iterations I            repeated prove/verify samples\n"
        << "  --required-proof-depth LEVEL  trace preparation depth floor\n"
        << "  --packing-repetitions T  diagnostic packing tests (default 120)\n"
        << "  --fresh-rns-limbs L       fresh data-chain prime count\n"
        << "  --bits-per-limb B         data-prime/Mock limb bits\n"
        << "  --data-prime-bits b0,...  mixed data-prime widths, bottom first\n"
        << "  --data-primes q0,...      exact data primes, bottom first\n"
        << "  --special-prime-bits B    SEAL key-switching prime bits\n"
        << "  --special-prime q         exact key-switching prime\n"
        << "  --security none|tc128     SEAL parameter validation\n"
        << "  --max-ciphertext-modulus-bits B  exact fresh-data cap\n"
        << "  --max-key-modulus-bits B  exact cap including special prime\n"
        << "  --initial-noise-margin-bits B  Mock only\n"
        << "  --rotation-noise-bits B        Mock only\n"
        << "  --relinearization-noise-bits B Mock only\n"
        << "  --gate-table-max-entries E  compact sparse support cap\n"
        << "  --run-tier unit|target-measured\n"
        << "  --result-file PATH       publish only after an accepted run\n"
        << "  --progress-file PATH     flushed phase/layer/round JSONL\n";
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options options;
    bool slots_explicit = false;
    bool lanes_explicit = false;
    bool proof_depth_explicit = false;
    bool fresh_limbs_explicit = false;
    bool limb_bits_explicit = false;
    bool data_chain_explicit = false;
    bool data_prime_bits_explicit = false;
    bool exact_data_primes_explicit = false;
    bool special_bits_explicit = false;
    bool exact_special_prime_explicit = false;
    bool ciphertext_cap_explicit = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            print_usage(std::cout);
            return std::nullopt;
        }
        if (index + 1 == argc) {
            throw std::invalid_argument("missing value after " +
                                        std::string(argument));
        }
        const std::string_view value(argv[++index]);
        if (argument == "--backend") {
            options.backend = parse_backend(value);
        } else if (argument == "--protocol") {
            options.protocol = parse_protocol(value);
        } else if (argument == "--gate-mle") {
            options.gate_mle = parse_gate_mle_profile(value);
        } else if (argument == "--workload") {
            options.workload = parse_workload(value);
        } else if (argument == "--slots") {
            options.slots = parse_size(value, argument);
            slots_explicit = true;
        } else if (argument == "--lanes") {
            options.lanes = parse_size(value, argument);
            lanes_explicit = true;
        } else if (argument == "--depth") {
            options.depth = parse_size(value, argument);
        } else if (argument == "--width") {
            options.width = parse_size(value, argument);
        } else if (argument == "--seed") {
            options.seed = parse_size(value, argument);
        } else if (argument == "--iterations") {
            options.iterations = parse_size(value, argument);
        } else if (argument == "--required-proof-depth") {
            options.required_proof_depth = parse_size(value, argument);
            proof_depth_explicit = true;
        } else if (argument == "--packing-repetitions") {
            options.packing_repetitions = parse_size(value, argument);
        } else if (argument == "--fresh-rns-limbs") {
            options.fresh_rns_limbs = parse_size(value, argument);
            fresh_limbs_explicit = true;
        } else if (argument == "--bits-per-limb") {
            options.bits_per_limb = parse_size(value, argument);
            limb_bits_explicit = true;
        } else if (argument == "--data-prime-bits") {
            options.data_prime_bit_sizes = parse_bit_sizes(value, argument);
            options.exact_data_primes.clear();
            options.exact_special_prime = 0;
            data_chain_explicit = true;
            data_prime_bits_explicit = true;
            options.modulus_chain_profile = "caller-mixed-width-candidate";
        } else if (argument == "--data-primes") {
            options.exact_data_primes = parse_primes(value, argument);
            options.data_prime_bit_sizes.clear();
            data_chain_explicit = true;
            exact_data_primes_explicit = true;
            options.modulus_chain_profile = "caller-exact-candidate";
        } else if (argument == "--special-prime-bits") {
            options.special_prime_bits = parse_size(value, argument);
            special_bits_explicit = true;
        } else if (argument == "--special-prime") {
            options.exact_special_prime = static_cast<std::uint64_t>(
                parse_size(value, argument));
            exact_special_prime_explicit = true;
        } else if (argument == "--max-ciphertext-modulus-bits") {
            options.max_ciphertext_modulus_bits = parse_size(value, argument);
            ciphertext_cap_explicit = true;
        } else if (argument == "--max-key-modulus-bits") {
            options.max_key_modulus_bits = parse_size(value, argument);
        } else if (argument == "--security") {
            options.security = value;
        } else if (argument == "--initial-noise-margin-bits") {
            options.initial_noise_margin_bits = parse_size(value, argument);
        } else if (argument == "--rotation-noise-bits") {
            options.rotation_noise_bits = parse_size(value, argument);
        } else if (argument == "--relinearization-noise-bits") {
            options.relinearization_noise_bits = parse_size(value, argument);
        } else if (argument == "--gate-table-max-entries") {
            options.gate_table_max_entries = parse_size(value, argument);
        } else if (argument == "--run-tier") {
            options.run_tier = value;
        } else if (argument == "--result-file") {
            if (!options.result_file.empty()) {
                throw std::invalid_argument(
                    "--result-file was specified twice");
            }
            if (value.empty()) {
                throw std::invalid_argument(
                    "--result-file expects a nonempty path");
            }
            options.result_file = std::filesystem::path(value);
        } else if (argument == "--progress-file") {
            if (!options.progress_file.empty()) {
                throw std::invalid_argument(
                    "--progress-file was specified twice");
            }
            if (value.empty()) {
                throw std::invalid_argument(
                    "--progress-file expects a nonempty path");
            }
            options.progress_file = std::filesystem::path(value);
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }
    if (data_prime_bits_explicit && exact_data_primes_explicit) {
        throw std::invalid_argument(
            "--data-prime-bits and --data-primes are mutually exclusive");
    }
    if (data_chain_explicit && limb_bits_explicit) {
        throw std::invalid_argument(
            "an explicit data-prime chain cannot be combined with "
            "--bits-per-limb");
    }
    if (special_bits_explicit && exact_special_prime_explicit) {
        throw std::invalid_argument(
            "--special-prime-bits and --special-prime are mutually "
            "exclusive");
    }
    if (exact_special_prime_explicit && !exact_data_primes_explicit) {
        throw std::invalid_argument(
            "--special-prime requires an exact --data-primes chain");
    }
    if (exact_data_primes_explicit && !exact_special_prime_explicit) {
        throw std::invalid_argument(
            "--data-primes requires an exact --special-prime");
    }
    if (!slots_explicit) {
        if (options.backend == BackendKind::Seal) {
            options.slots = 1024;
        } else if (options.protocol == ProtocolKind::Folded ||
                   options.protocol == ProtocolKind::Laned) {
            // The selected packing layout needs room for a complete fixed
            // message plus at least two source/destination cosets.
            options.slots = 32;
        }
    }
    if (options.backend == BackendKind::Mock &&
        options.protocol != ProtocolKind::Base && !limb_bits_explicit) {
        // Mock's coefficient-transform scale intentionally models base-17
        // digit masks. Wide limbs keep this structural test from confusing
        // its synthetic noise counter with real parameter selection.
        options.bits_per_limb = 300;
    }
    if (options.protocol == ProtocolKind::Folded) {
        if (!proof_depth_explicit) {
            options.required_proof_depth =
                kConservativeFoldedMultiplicationProofDepth;
        }
        if (!fresh_limbs_explicit) {
            options.fresh_rns_limbs = packed_candidate_limb_count(
                options.required_proof_depth, options.depth);
        }
    }
    if (options.protocol == ProtocolKind::Laned) {
        if (!lanes_explicit) {
            options.lanes = options.slots / 4;
        }
        if (!proof_depth_explicit) {
            options.required_proof_depth =
                conservative_laned_multiplication_proof_depth(
                    options.lanes, options.slots);
        }
        if (!fresh_limbs_explicit) {
            options.fresh_rns_limbs = packed_candidate_limb_count(
                options.required_proof_depth, options.depth);
        }
        if (options.backend == BackendKind::Seal &&
            !ciphertext_cap_explicit) {
            options.max_ciphertext_modulus_bits = 660;
        }
    } else if (lanes_explicit) {
        throw std::invalid_argument("--lanes is only valid for Laned");
    }
    if (options.backend == BackendKind::Seal &&
        (options.protocol == ProtocolKind::Folded ||
         options.protocol == ProtocolKind::Laned) &&
        !special_bits_explicit && !exact_special_prime_explicit) {
        options.special_prime_bits = 60;
    }
    if (options.backend == BackendKind::Seal &&
        (options.protocol == ProtocolKind::Folded ||
         options.protocol == ProtocolKind::Laned) &&
        !data_chain_explicit && !limb_bits_explicit) {
        options.data_prime_bit_sizes = packed_candidate_limb_widths(
            options.fresh_rns_limbs);
        options.modulus_chain_profile =
            options.protocol == ProtocolKind::Folded
                ? "folded-mixed-width-honest-candidate-not-theorem-certified"
                : "laned-mixed-width-honest-candidate-not-theorem-certified";
    }
    if (data_chain_explicit) {
        const std::size_t chain_size =
            options.data_prime_bit_sizes.empty()
                ? options.exact_data_primes.size()
                : options.data_prime_bit_sizes.size();
        if (fresh_limbs_explicit && options.fresh_rns_limbs != chain_size) {
            throw std::invalid_argument(
                "--fresh-rns-limbs disagrees with the explicit data chain");
        }
        options.fresh_rns_limbs = chain_size;
    }
    if (options.protocol == ProtocolKind::Folded ||
        options.protocol == ProtocolKind::Laned) {
        const std::size_t policy_proof_depth =
            options.protocol == ProtocolKind::Folded
                ? kConservativeFoldedMultiplicationProofDepth
                : conservative_laned_multiplication_proof_depth(
                      options.lanes, options.slots);
        if (options.required_proof_depth < policy_proof_depth) {
            throw std::invalid_argument(
                "--required-proof-depth is below the fixed conservative "
                "packed proof-ingress policy");
        }
        const std::size_t minimum_limbs = packed_candidate_limb_count(
            options.required_proof_depth, options.depth);
        if (options.fresh_rns_limbs < minimum_limbs) {
            throw std::invalid_argument(
                "packed candidate RNS chain is too short for the requested "
                "proof ingress and payload depth");
        }
    } else if (options.packing_repetitions !=
               kPackingWellFormednessRepetitions) {
        throw std::invalid_argument(
            "--packing-repetitions is only valid for Folded or Laned");
    }
    if (!options.exact_data_primes.empty()) {
        options.special_prime_bits =
            std::bit_width(options.exact_special_prime);
    }
    if (options.slots < 2 || !std::has_single_bit(options.slots)) {
        throw std::invalid_argument("--slots must be a power of two >= 2");
    }
    if (options.depth == 0 ||
        options.depth > kMaximumPayloadMultiplicativeDepth ||
        options.width == 0 ||
        options.iterations == 0 || options.fresh_rns_limbs == 0 ||
        options.packing_repetitions == 0 ||
        options.bits_per_limb == 0 || options.gate_table_max_entries == 0) {
        throw std::invalid_argument(
            "payload depth must be in 1..8; width, iterations, packing "
            "repetitions, limbs, limb bits, and the gate-table cap must be "
            "nonzero");
    }
    if (options.security != "none" && options.security != "tc128") {
        throw std::invalid_argument("--security must be none or tc128");
    }
    if (options.backend == BackendKind::Mock && options.security != "none") {
        throw std::invalid_argument("Mock supports only --security none");
    }
    if (options.backend == BackendKind::Mock && data_chain_explicit) {
        throw std::invalid_argument(
            "mixed or exact coefficient primes require --backend seal-bgv");
    }
    if (options.run_tier != "unit" &&
        options.run_tier != "target-measured") {
        throw std::invalid_argument(
            "--run-tier must be unit or target-measured");
    }
    const std::size_t unit_limit =
        options.backend == BackendKind::Mock ? 256 : 1024;
    if (options.run_tier == "unit" && options.slots > unit_limit) {
        throw std::invalid_argument(
            "this allocation requires target-measured");
    }
    if (options.backend == BackendKind::Seal && options.slots < 1024) {
        throw std::invalid_argument("SEAL requires --slots >= 1024");
    }
    if (options.protocol == ProtocolKind::Folded &&
        options.slots < 2 * kExtensionDegree) {
        throw std::invalid_argument("Folded requires --slots >= 16");
    }
    if (options.protocol == ProtocolKind::Laned &&
        (options.slots < 2 * kExtensionDegree || options.lanes == 0 ||
         !std::has_single_bit(options.lanes) ||
         options.lanes > options.slots)) {
        throw std::invalid_argument(
            "Laned requires N >= 16 and power-of-two 1 <= B <= N");
    }
    if (options.protocol == ProtocolKind::Laned &&
        options.workload == WorkloadKind::RotationHeavy) {
        throw std::invalid_argument(
            "rotation-heavy workloads are not valid for Laned");
    }
    if (options.backend == BackendKind::Seal &&
        (options.bits_per_limb < 20 || options.bits_per_limb > 60 ||
         options.special_prime_bits < 20 ||
         options.special_prime_bits > 60)) {
        throw std::invalid_argument("SEAL coefficient primes use 20..60 bits");
    }
    if (!options.data_prime_bit_sizes.empty() &&
        (options.data_prime_bit_sizes.front() != 60 ||
         std::any_of(options.data_prime_bit_sizes.begin() + 1,
                     options.data_prime_bit_sizes.end(),
                     [](int bits) { return bits < 18 || bits > 60; }))) {
        throw std::invalid_argument(
            "mixed data-prime widths require 60-bit q0 and 18..60-bit heads");
    }
    if (!options.exact_data_primes.empty() &&
        (options.exact_data_primes.front() != kOuterFieldOrder ||
         options.exact_special_prime == 0)) {
        throw std::invalid_argument(
            "exact data primes require q0=Q and an exact special prime");
    }
    if (!options.result_file.empty() && !options.progress_file.empty() &&
        std::filesystem::absolute(options.result_file).lexically_normal() ==
            std::filesystem::absolute(options.progress_file)
                .lexically_normal()) {
        throw std::invalid_argument(
            "--result-file and --progress-file must be different paths");
    }
    if (options.exact_data_primes.empty() &&
        options.exact_special_prime != 0) {
        throw std::invalid_argument(
            "--special-prime requires --data-primes");
    }
    if (options.security == "tc128" &&
        options.run_tier != "target-measured") {
        throw std::invalid_argument(
            "tc128 runs require --run-tier target-measured");
    }
    return options;
}

template <fhe::FheBackend Backend, typename Function>
void for_each_proof_ciphertext(const EncryptedBaseProof<Backend> &proof,
                               Function function) {
    const auto extension = [&](const fhe::ExtensionValue<Backend> &value,
                               const std::string &checkpoint) {
        for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
             ++coefficient) {
            if (value[coefficient].is_encrypted()) {
                function(value[coefficient].ciphertext(),
                         checkpoint + "/coefficient/" +
                             std::to_string(coefficient));
            }
        }
    };
    for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
        const auto &reduction = proof.reductions[layer];
        if (const auto *affine =
                std::get_if<EncryptedBaseAffineLayerReduction<Backend>>(
                    &reduction)) {
            for (std::size_t round = 0; round < affine->rounds.size(); ++round) {
                for (std::size_t evaluation = 0; evaluation < 2;
                     ++evaluation) {
                    extension(
                        affine->rounds[round].evaluations[evaluation],
                        "layer/" + std::to_string(layer) + "/round/" +
                            std::to_string(round) + "/evaluation/" +
                            std::to_string(evaluation + 1));
                }
            }
            extension(affine->source_vector,
                      "layer/" + std::to_string(layer) +
                          "/terminal/source");
        } else {
            const auto &multiplication =
                std::get<EncryptedBaseMultiplicationLayerReduction<Backend>>(
                    reduction);
            for (std::size_t round = 0;
                 round < multiplication.rounds.size(); ++round) {
                for (std::size_t evaluation = 0; evaluation < 2;
                     ++evaluation) {
                    extension(
                        multiplication.rounds[round]
                            .evaluations[evaluation],
                        "layer/" + std::to_string(layer) + "/round/" +
                            std::to_string(round) + "/evaluation/" +
                            std::to_string(evaluation + 1));
                }
            }
            extension(multiplication.source_vectors[0],
                      "layer/" + std::to_string(layer) +
                          "/terminal/left");
            extension(multiplication.source_vectors[1],
                      "layer/" + std::to_string(layer) +
                          "/terminal/right");
        }
    }
}

template <fhe::FheBackend Backend, typename Function>
void for_each_proof_ciphertext(const EncryptedFoldedProof<Backend> &proof,
                               Function function) {
    for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
        const auto &reduction = proof.reductions[layer];
        if (const auto *affine =
                std::get_if<EncryptedFoldedAffineLayerReduction<Backend>>(
                    &reduction)) {
            for (std::size_t round = 0; round < affine->rounds.size();
                 ++round) {
                function(affine->rounds[round].packed_evaluations,
                         "layer/" + std::to_string(layer) + "/round/" +
                             std::to_string(round) + "/packed-evaluations");
            }
            function(affine->packed_terminal_value,
                     "layer/" + std::to_string(layer) +
                         "/terminal/packed-source");
        } else {
            const auto &multiplication = std::get<
                EncryptedFoldedMultiplicationLayerReduction<Backend>>(reduction);
            for (std::size_t round = 0;
                 round < multiplication.rounds.size(); ++round) {
                function(
                    multiplication.rounds[round].packed_evaluations,
                    "layer/" + std::to_string(layer) + "/round/" +
                        std::to_string(round) + "/packed-evaluations");
            }
            function(multiplication.packed_source_values,
                     "layer/" + std::to_string(layer) +
                         "/terminal/packed-sources");
        }
    }
}

template <fhe::FheBackend Backend, typename Function>
void for_each_proof_ciphertext(const EncryptedLanedProof<Backend> &proof,
                               Function function) {
    for (std::size_t layer = 0; layer < proof.reductions.size(); ++layer) {
        const auto &reduction = proof.reductions[layer];
        if (const auto *affine =
                std::get_if<EncryptedLanedAffineLayerReduction<Backend>>(
                    &reduction)) {
            for (std::size_t round = 0; round < affine->rounds.size();
                 ++round) {
                function(affine->rounds[round].packed_evaluations,
                         "layer/" + std::to_string(layer) + "/round/" +
                             std::to_string(round) + "/packed-evaluations");
            }
            function(affine->packed_terminal_value,
                     "layer/" + std::to_string(layer) +
                         "/terminal/packed-weighted-source");
        } else {
            const auto &multiplication = std::get<
                EncryptedLanedMultiplicationLayerReduction<Backend>>(reduction);
            for (std::size_t round = 0;
                 round < multiplication.rounds.size(); ++round) {
                function(
                    multiplication.rounds[round].packed_evaluations,
                    "layer/" + std::to_string(layer) + "/round/" +
                        std::to_string(round) + "/packed-evaluations");
            }
            function(multiplication.packed_source_values,
                     "layer/" + std::to_string(layer) +
                         "/terminal/packed-sources");
        }
    }
}

template <packing::CoefficientWellFormednessBackend Backend,
          typename Function>
void for_each_packing_ciphertext(
    const TranscriptPackingProof<Backend> &packing, Function function) {
    for (std::size_t index = 0;
         index < packing.well_formedness_reveals.size(); ++index) {
        if (packing.well_formedness_reveals[index]) {
            function(*packing.well_formedness_reveals[index],
                     "packing/well-formedness/" + std::to_string(index));
        }
    }
    for (std::size_t index = 0;
         index < packing.digit_decomposed_packed_values.size();
         ++index) {
        if (packing.digit_decomposed_packed_values[index]) {
            function(
                *packing.digit_decomposed_packed_values[index],
                "packing/digit/" + std::to_string(index));
        }
    }
}

/// Visit physical ciphertexts in a selected proof. GKR itself contains only
/// hash commitments, so all ciphertexts live in this packing artifact.
template <packing::CoefficientWellFormednessBackend Backend,
          typename Function>
void for_each_proof_ciphertext(const LaminateFoldedProof<Backend> &proof,
                               Function function) {
    for_each_packing_ciphertext<Backend>(proof.transcript_packing,
                                         std::move(function));
}

template <packing::CoefficientWellFormednessBackend Backend,
          typename Function>
void for_each_proof_ciphertext(const LaminateLanedProof<Backend> &proof,
                               Function function) {
    for_each_packing_ciphertext<Backend>(proof.transcript_packing,
                                         std::move(function));
}

template <fhe::FheBackend Backend, typename Proof>
CiphertextMeasurements<Backend> measure_proof_ciphertexts(
    const typename Backend::EvalContext &eval,
    const Proof &proof) {
    CiphertextMeasurements<Backend> result;
    for_each_proof_ciphertext<Backend>(
        proof, [&](const auto &ciphertext, const std::string &checkpoint) {
            result.observe(eval, ciphertext, checkpoint);
        });
    return result;
}

template <fhe::FheBackend Backend>
CiphertextMeasurements<Backend> measure_trace_ciphertexts(
    const typename Backend::EvalContext &eval,
    const EncryptedTrace<Backend> &trace) {
    CiphertextMeasurements<Backend> result;
    for (std::size_t layer = 0; layer < trace.layers.size(); ++layer) {
        for (std::size_t wire = 0;
             wire < trace.layers[layer].wires.size(); ++wire) {
            const fhe::FheValue<Backend> &value =
                trace.layers[layer].wires[wire];
            if (value.is_encrypted()) {
                result.observe(
                    eval, value.ciphertext(),
                    "layer/" + std::to_string(layer) + "/wire/" +
                        std::to_string(wire));
            }
        }
    }
    return result;
}

struct MeasuredNoise {
    std::vector<double> budgets;
    int minimum = std::numeric_limits<int>::max();
    std::string minimum_checkpoint = "none";

    void observe(int budget, const std::string &checkpoint) {
        budgets.push_back(static_cast<double>(budget));
        if (budget < minimum) {
            minimum = budget;
            minimum_checkpoint = checkpoint;
        }
    }
};

struct FormulaMeasuredCounts {
    std::uint64_t plain_multiplications = 0;
    std::uint64_t ciphertext_multiplications_no_relinearization = 0;
    std::uint64_t relinearizations = 0;
    std::uint64_t negations = 0;
    std::uint64_t additions = 0;
    std::uint64_t rotations = 0;
    std::uint64_t extension_additions = 0;
    std::uint64_t extension_subtractions = 0;
    std::uint64_t extension_ciphertext_multiplications = 0;
    std::uint64_t extension_plain_multiplications = 0;
};

template <typename Backend> struct BackendAdapter;

template <> struct BackendAdapter<MockBackend> {
    using Counts = OperationCounts;
    static constexpr bool has_invariant_noise = false;

    static MockBackend::Contexts create(const Options &options) {
        return MockBackend::create(MockParameters{
            options.slots,
            options.fresh_rns_limbs,
            options.bits_per_limb,
            options.initial_noise_margin_bits,
            options.rotation_noise_bits,
            options.relinearization_noise_bits});
    }

    static void begin(const MockBackend::EvalContext &eval) {
        MockBackend::reset_counts(eval);
    }

    static Counts finish(const MockBackend::EvalContext &eval) {
        return MockBackend::counts(eval);
    }

    static Counts snapshot(const MockBackend::EvalContext &eval) {
        return MockBackend::counts(eval);
    }

    static std::uint64_t decrypt_calls(const Counts &counts) {
        return counts.decrypt;
    }

    static FormulaMeasuredCounts formula_counts(const Counts &counts) {
        return FormulaMeasuredCounts{
            counts.mul_plain_scalar + counts.mul_plain_vector,
            counts.mul_no_relin,
            counts.relinearize,
            counts.negate,
            counts.add,
            counts.rotate,
            counts.logical_ext_add,
            counts.logical_ext_sub,
            counts.logical_ext_mul,
            counts.logical_ext_mul_plain};
    }

    static void emit_operation_counts(const Record &record,
                                      std::string_view stage,
                                      const Counts &counts) {
        emit_counts(record, stage, counts);
    }

    static void emit_parameters(const Record &record, const Options &options,
                                const MockBackend::EvalContext &) {
        record.text("parameters.security_level", "mock-not-cryptographic");
        record.integer("parameters.bits_per_limb", options.bits_per_limb);
        record.integer("parameters.initial_noise_margin_bits",
                       options.initial_noise_margin_bits);
        record.integer("parameters.rotation_noise_bits",
                       options.rotation_noise_bits);
        record.integer("parameters.relinearization_noise_bits",
                       options.relinearization_noise_bits);
        record.text("parameters.coeff_modulus_primes",
                    "not-modeled-by-mock");
        record.text("parameters.coeff_modulus_bit_widths",
                    join(std::vector<std::size_t>(options.fresh_rns_limbs,
                                                  options.bits_per_limb)));
        record.text("parameters.bgv_correction_factor_schedule",
                    "not-modeled-by-mock");
        record.text("parameters.special_prime", "not-modeled-by-mock");
        record.text("parameters.galois_keys", "not-modeled-by-mock");
        record.text("parameters.serialization", "mock-canonical-v2-lossless");
        record.text("operations.rns_bucketing",
                    "aggregate-only-not-yet-bucketed");
    }
};

#ifdef LAMINATE_WITH_SEAL
template <> struct BackendAdapter<SealBackend> {
    using Counts = SealBackend::OperationCounts;
    static constexpr bool has_invariant_noise = true;

    static SealBackend::Contexts create(const Options &options) {
        return SealBackend::create(SealParameters{
            .poly_modulus_degree = options.slots,
            .fresh_rns_limbs = options.fresh_rns_limbs,
            .data_prime_bit_sizes = options.data_prime_bit_sizes,
            .exact_data_primes = options.exact_data_primes,
            .exact_special_prime = options.exact_special_prime,
            .bits_per_data_prime =
                static_cast<int>(options.bits_per_limb),
            .special_prime_bits =
                static_cast<int>(options.special_prime_bits),
            .security_level =
                options.security == "tc128" ? seal::sec_level_type::tc128
                                             : seal::sec_level_type::none,
            .max_fresh_ciphertext_modulus_bits =
                options.max_ciphertext_modulus_bits,
            .max_key_modulus_bits = options.max_key_modulus_bits,
        });
    }

    static void begin(const SealBackend::EvalContext &eval) {
        SealBackend::reset_counts(eval);
        SealBackend::set_counting(eval, true);
    }

    static Counts finish(const SealBackend::EvalContext &eval) {
        SealBackend::set_counting(eval, false);
        return SealBackend::counts(eval);
    }

    static Counts snapshot(const SealBackend::EvalContext &eval) {
        return SealBackend::counts(eval);
    }

    static std::uint64_t decrypt_calls(const Counts &counts) {
        return counts.calls(SealBackend::OperationKind::Decrypt);
    }

    static FormulaMeasuredCounts formula_counts(const Counts &counts) {
        using Kind = SealBackend::OperationKind;
        return FormulaMeasuredCounts{
            counts.calls(Kind::MulPlainScalar) +
                counts.calls(Kind::MulPlainVector),
            counts.calls(Kind::MulNoRelin),
            counts.calls(Kind::Relinearize),
            counts.calls(Kind::Negate),
            counts.calls(Kind::Add),
            counts.calls(Kind::Rotate),
            counts.calls(Kind::LogicalExtAdd),
            counts.calls(Kind::LogicalExtSub),
            counts.calls(Kind::LogicalExtMul),
            counts.calls(Kind::LogicalExtMulPlain)};
    }

    static void emit_operation_counts(const Record &record,
                                      std::string_view stage,
                                      const Counts &counts) {
        const std::string prefix =
            "operations." + std::string(stage) + '.';
        for (std::size_t index = 0;
             index < static_cast<std::size_t>(
                         SealBackend::OperationKind::Count);
             ++index) {
            const auto kind =
                static_cast<SealBackend::OperationKind>(index);
            const std::string operation = SealBackend::operation_name(kind);
            record.integer(prefix + operation + ".calls",
                           counts.calls(kind));
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

    static void emit_parameters(const Record &record, const Options &options,
                                const SealBackend::EvalContext &eval) {
        const std::vector<std::uint64_t> primes =
            SealBackend::coefficient_moduli(eval);
        std::vector<std::size_t> widths;
        widths.reserve(primes.size());
        for (std::size_t index = 0; index < options.fresh_rns_limbs;
             ++index) {
            const std::uint64_t prime = primes.at(index);
            if (prime % kBaseFieldOrder != 1) {
                throw std::logic_error(
                    "SEAL data prime does not preserve the BGV correction "
                    "factor");
            }
        }
        for (const std::uint64_t prime : primes) {
            widths.push_back(std::bit_width(prime));
        }
        record.text("parameters.security_level",
                    options.security == "tc128" ? "tc128" : "none");
        record.text("parameters.privacy_claim",
                    options.security == "tc128"
                        ? "SEAL-tc128-validation"
                        : "none-not-a-privacy-parameter-set");
        if (options.data_prime_bit_sizes.empty() &&
            options.exact_data_primes.empty()) {
            record.integer("parameters.bits_per_limb",
                           options.bits_per_limb);
        } else {
            record.text("parameters.bits_per_limb", "not-applicable");
        }
        record.text("parameters.data_prime_shape",
                    !options.exact_data_primes.empty()
                        ? "exact-bottom-to-top"
                        : (!options.data_prime_bit_sizes.empty()
                               ? "mixed-width-bottom-to-top"
                               : "uniform-head-width-benchmark-fixture"));
        record.text("parameters.coeff_modulus_primes", join(primes));
        record.text("parameters.coeff_modulus_bit_widths", join(widths));
        record.text("parameters.bgv_correction_factor_schedule",
                    "unit-preserving-lcm-2N-t-primes");
        record.integer("parameters.special_prime", primes.back());
        record.integer("parameters.special_prime_bits", widths.back());
        record.integer("parameters.fresh_ciphertext_modulus_bits",
                       SealBackend::fresh_ciphertext_modulus_bits(eval));
        record.integer(
            "parameters.fresh_ciphertext_modulus_width_sum_bits",
            SealBackend::fresh_ciphertext_modulus_width_sum_bits(eval));
        record.integer("parameters.key_modulus_bits",
                       SealBackend::key_modulus_bits(eval));
        record.integer("parameters.key_modulus_width_sum_bits",
                       SealBackend::key_modulus_width_sum_bits(eval));
        record.integer("parameters.max_fresh_ciphertext_modulus_bits",
                       options.max_ciphertext_modulus_bits);
        record.integer("parameters.max_key_modulus_bits",
                       options.max_key_modulus_bits);
        record.text("parameters.galois_keys",
                    "power-of-two-row-rotations-and-column-swap");
        record.text("parameters.serialization", "seal-uncompressed-v4.1");
        record.text("operations.rns_bucketing", "exact-by-input-rns-limb");
    }
};

#endif

std::string layer_kind_name(LayerKind kind) {
    switch (kind) {
    case LayerKind::Affine:
        return "affine";
    case LayerKind::Multiplication:
        return "multiplication";
    case LayerKind::Input:
        return "input";
    }
    throw std::logic_error("unknown layer kind");
}

void emit_schedule_operations(const Record &record,
                              const std::string &prefix,
                              const ScheduleOperations &operations) {
#define LAMINATE_EMIT_FORMULA(field)                                           \
    record.integer(prefix + '.' + #field, operations.field)
    LAMINATE_EMIT_FORMULA(weighted_base_terms);
    LAMINATE_EMIT_FORMULA(online_vector_weighted_base_terms);
    LAMINATE_EMIT_FORMULA(weighted_base_accumulations);
    LAMINATE_EMIT_FORMULA(base_ciphertext_multiplications);
    LAMINATE_EMIT_FORMULA(base_additions);
    LAMINATE_EMIT_FORMULA(base_subtractions);
    LAMINATE_EMIT_FORMULA(base_negations);
    LAMINATE_EMIT_FORMULA(base_rotations);
    LAMINATE_EMIT_FORMULA(extension_plain_multiplications);
    LAMINATE_EMIT_FORMULA(
        online_vector_extension_plain_multiplications);
    LAMINATE_EMIT_FORMULA(extension_ciphertext_multiplications);
    LAMINATE_EMIT_FORMULA(extension_additions);
    LAMINATE_EMIT_FORMULA(extension_subtractions);
    LAMINATE_EMIT_FORMULA(extension_rotations);
    LAMINATE_EMIT_FORMULA(extension_folds);
    LAMINATE_EMIT_FORMULA(extension_relinearizations);
    LAMINATE_EMIT_FORMULA(witness_base_plain_multiplications);
    LAMINATE_EMIT_FORMULA(witness_base_additions);
    LAMINATE_EMIT_FORMULA(round_extension_values);
    LAMINATE_EMIT_FORMULA(aligned_round_ciphertexts);
    LAMINATE_EMIT_FORMULA(logical_rounds);
    LAMINATE_EMIT_FORMULA(terminal_messages);
#undef LAMINATE_EMIT_FORMULA
}

bool emit_measured_bound_comparison(const Record &record,
                                    std::string_view metric,
                                    std::uint64_t measured,
                                    std::uint64_t upper_bound) {
    const FormulaComparisonStatus status =
        compare_measured_to_upper_bound(measured, upper_bound);
    const std::string prefix =
        "formula.measured_vs_conservative_upper." + std::string(metric);
    record.integer(prefix + ".measured", measured);
    record.integer(prefix + ".upper", upper_bound);
    record.text(prefix + ".status",
                std::string(comparison_status_name(status)));
    return status != FormulaComparisonStatus::Investigate;
}

void emit_schedule_formula(const Record &record,
                           const ScheduleFormula &formula,
                           const FormulaMeasuredCounts *measured,
                           std::size_t slot_count) {
    record.text("formula.version", "schedule-v4");
    record.text("formula.protocol",
                std::string(schedule_protocol_name(formula.protocol)));
    record.text("formula.scope",
                "proof-generation-including-witness-and-round-encoding");
    record.text("formula.conservatism",
                "upper-bound-with-structural-gate-zero-elision");
    record.text("formula.excludes",
                "transport-mod-switches");
    emit_schedule_operations(record, "formula.operations.total",
                             formula.operations);

    const ConcretePrimitiveUpperBound concrete =
        concrete_primitive_upper_bound(formula.operations, slot_count);
    record.integer("formula.concrete_upper.plain_multiplications",
                   concrete.plain_multiplications);
    record.integer(
        "formula.concrete_upper.online_vector_plain_multiplications",
        concrete.online_vector_plain_multiplications);
    record.integer(
        "formula.concrete_upper.online_vector_plaintext_preparations",
        concrete.online_vector_plaintext_preparations);
    record.integer(
        "formula.concrete_upper.ciphertext_multiplications_no_relinearization",
        concrete.ciphertext_multiplications_no_relinearization);
    record.integer("formula.concrete_upper.relinearizations",
                   concrete.relinearizations);
    record.integer("formula.concrete_upper.negations", concrete.negations);
    record.integer("formula.concrete_upper.additions", concrete.additions);
    record.integer("formula.concrete_upper.subtractions",
                   concrete.subtractions);
    record.integer("formula.concrete_upper.rotations", concrete.rotations);
    if (measured != nullptr) {
        bool within_bound = true;
        within_bound &= emit_measured_bound_comparison(
            record, "plain_multiplications", measured->plain_multiplications,
            concrete.plain_multiplications);
        within_bound &= emit_measured_bound_comparison(
            record, "ciphertext_multiplications_no_relinearization",
            measured->ciphertext_multiplications_no_relinearization,
            concrete.ciphertext_multiplications_no_relinearization);
        within_bound &= emit_measured_bound_comparison(
            record, "relinearizations", measured->relinearizations,
            concrete.relinearizations);
        within_bound &= emit_measured_bound_comparison(
            record, "negations", measured->negations, concrete.negations);
        within_bound &= emit_measured_bound_comparison(
            record, "additions", measured->additions, concrete.additions);
        within_bound &= emit_measured_bound_comparison(
            record, "rotations", measured->rotations, concrete.rotations);
        within_bound &= emit_measured_bound_comparison(
            record, "extension_additions", measured->extension_additions,
            formula.operations.extension_additions);
        within_bound &= emit_measured_bound_comparison(
            record, "extension_subtractions",
            measured->extension_subtractions,
            formula.operations.extension_subtractions);
        within_bound &= emit_measured_bound_comparison(
            record, "extension_ciphertext_multiplications",
            measured->extension_ciphertext_multiplications,
            formula.operations.extension_ciphertext_multiplications);
        within_bound &= emit_measured_bound_comparison(
            record, "extension_plain_multiplications",
            measured->extension_plain_multiplications,
            formula.operations.extension_plain_multiplications);
        record.text("formula.measured_upper_bound_result",
                    within_bound ? "PASS" : "INVESTIGATE");
        if (!within_bound) {
            throw std::logic_error(
                "measured prover operation count exceeds schedule formula");
        }
    } else {
        record.text("formula.measured_upper_bound_result", "not-executed");
    }

    std::vector<std::string> kinds;
    std::vector<std::size_t> source_logical_live_wires;
    std::vector<std::size_t> source_stored_values;
    std::vector<std::size_t> source_encrypted_ciphertexts;
    std::vector<std::size_t> source_virtual_wire_positions;
    std::vector<std::size_t> source_materialized_packed_ciphertexts;
    std::vector<std::size_t> source_reused_packed_ciphertexts;
    std::vector<std::size_t> source_virtual_packed_positions;
    std::vector<std::size_t> reduction_domain_variables;
    std::vector<std::size_t> slot_variables;
#define LAMINATE_FORMULA_VECTOR(field) std::vector<std::uint64_t> field
    LAMINATE_FORMULA_VECTOR(weighted_base_terms);
    LAMINATE_FORMULA_VECTOR(weighted_base_accumulations);
    LAMINATE_FORMULA_VECTOR(base_ciphertext_multiplications);
    LAMINATE_FORMULA_VECTOR(base_additions);
    LAMINATE_FORMULA_VECTOR(base_subtractions);
    LAMINATE_FORMULA_VECTOR(base_negations);
    LAMINATE_FORMULA_VECTOR(base_rotations);
    LAMINATE_FORMULA_VECTOR(extension_plain_multiplications);
    LAMINATE_FORMULA_VECTOR(extension_ciphertext_multiplications);
    LAMINATE_FORMULA_VECTOR(extension_additions);
    LAMINATE_FORMULA_VECTOR(extension_subtractions);
    LAMINATE_FORMULA_VECTOR(extension_rotations);
    LAMINATE_FORMULA_VECTOR(extension_folds);
    LAMINATE_FORMULA_VECTOR(extension_relinearizations);
    LAMINATE_FORMULA_VECTOR(witness_base_plain_multiplications);
    LAMINATE_FORMULA_VECTOR(witness_base_additions);
    LAMINATE_FORMULA_VECTOR(round_extension_values);
    LAMINATE_FORMULA_VECTOR(aligned_round_ciphertexts);
    LAMINATE_FORMULA_VECTOR(logical_rounds);
    LAMINATE_FORMULA_VECTOR(terminal_messages);
#undef LAMINATE_FORMULA_VECTOR
    for (const ScheduleLayerFormula &layer : formula.layers) {
        kinds.push_back(layer_kind_name(layer.kind));
        source_logical_live_wires.push_back(
            layer.source_logical_live_wires);
        source_stored_values.push_back(layer.source_stored_values);
        source_encrypted_ciphertexts.push_back(
            layer.source_encrypted_ciphertexts);
        source_virtual_wire_positions.push_back(
            layer.source_virtual_wire_positions);
        source_materialized_packed_ciphertexts.push_back(
            layer.source_materialized_packed_ciphertexts);
        source_reused_packed_ciphertexts.push_back(
            layer.source_reused_packed_ciphertexts);
        source_virtual_packed_positions.push_back(
            layer.source_virtual_packed_positions);
        reduction_domain_variables.push_back(
            layer.reduction_domain_variables);
        slot_variables.push_back(layer.slot_variables);
#define LAMINATE_PUSH_FORMULA(field) field.push_back(layer.operations.field)
        LAMINATE_PUSH_FORMULA(weighted_base_terms);
        LAMINATE_PUSH_FORMULA(weighted_base_accumulations);
        LAMINATE_PUSH_FORMULA(base_ciphertext_multiplications);
        LAMINATE_PUSH_FORMULA(base_additions);
        LAMINATE_PUSH_FORMULA(base_subtractions);
        LAMINATE_PUSH_FORMULA(base_negations);
        LAMINATE_PUSH_FORMULA(base_rotations);
        LAMINATE_PUSH_FORMULA(extension_plain_multiplications);
        LAMINATE_PUSH_FORMULA(extension_ciphertext_multiplications);
        LAMINATE_PUSH_FORMULA(extension_additions);
        LAMINATE_PUSH_FORMULA(extension_subtractions);
        LAMINATE_PUSH_FORMULA(extension_rotations);
        LAMINATE_PUSH_FORMULA(extension_folds);
        LAMINATE_PUSH_FORMULA(extension_relinearizations);
        LAMINATE_PUSH_FORMULA(witness_base_plain_multiplications);
        LAMINATE_PUSH_FORMULA(witness_base_additions);
        LAMINATE_PUSH_FORMULA(round_extension_values);
        LAMINATE_PUSH_FORMULA(aligned_round_ciphertexts);
        LAMINATE_PUSH_FORMULA(logical_rounds);
        LAMINATE_PUSH_FORMULA(terminal_messages);
#undef LAMINATE_PUSH_FORMULA
    }
    const std::string prefix = "formula.operations.layers.";
    record.text(prefix + "kinds", join(kinds));
    record.text(prefix + "source_logical_live_wires",
                join(source_logical_live_wires));
    record.text(prefix + "source_stored_values",
                join(source_stored_values));
    record.text(prefix + "source_encrypted_ciphertexts",
                join(source_encrypted_ciphertexts));
    record.text(prefix + "source_virtual_wire_positions",
                join(source_virtual_wire_positions));
    record.text(prefix + "source_materialized_packed_ciphertexts",
                join(source_materialized_packed_ciphertexts));
    record.text(prefix + "source_reused_packed_ciphertexts",
                join(source_reused_packed_ciphertexts));
    record.text(prefix + "source_virtual_packed_positions",
                join(source_virtual_packed_positions));
    record.text(prefix + "reduction_domain_variables",
                join(reduction_domain_variables));
    record.text(prefix + "slot_variables", join(slot_variables));
#define LAMINATE_EMIT_FORMULA_VECTOR(field)                                    \
    record.text(prefix + #field, join(field))
    LAMINATE_EMIT_FORMULA_VECTOR(weighted_base_terms);
    LAMINATE_EMIT_FORMULA_VECTOR(weighted_base_accumulations);
    LAMINATE_EMIT_FORMULA_VECTOR(base_ciphertext_multiplications);
    LAMINATE_EMIT_FORMULA_VECTOR(base_additions);
    LAMINATE_EMIT_FORMULA_VECTOR(base_subtractions);
    LAMINATE_EMIT_FORMULA_VECTOR(base_negations);
    LAMINATE_EMIT_FORMULA_VECTOR(base_rotations);
    LAMINATE_EMIT_FORMULA_VECTOR(extension_plain_multiplications);
    LAMINATE_EMIT_FORMULA_VECTOR(extension_ciphertext_multiplications);
    LAMINATE_EMIT_FORMULA_VECTOR(extension_additions);
    LAMINATE_EMIT_FORMULA_VECTOR(extension_subtractions);
    LAMINATE_EMIT_FORMULA_VECTOR(extension_rotations);
    LAMINATE_EMIT_FORMULA_VECTOR(extension_folds);
    LAMINATE_EMIT_FORMULA_VECTOR(extension_relinearizations);
    LAMINATE_EMIT_FORMULA_VECTOR(witness_base_plain_multiplications);
    LAMINATE_EMIT_FORMULA_VECTOR(witness_base_additions);
    LAMINATE_EMIT_FORMULA_VECTOR(round_extension_values);
    LAMINATE_EMIT_FORMULA_VECTOR(aligned_round_ciphertexts);
    LAMINATE_EMIT_FORMULA_VECTOR(logical_rounds);
    LAMINATE_EMIT_FORMULA_VECTOR(terminal_messages);
#undef LAMINATE_EMIT_FORMULA_VECTOR
}

void emit_cross_round_packing_requirement(
    const Record &record, bool required, std::size_t aligned_ciphertexts,
    std::size_t well_formedness_reveals) {
    record.text("protocol.cross_round_transport.policy",
                required ? "mandatory-full-aligned-transcript"
                         : "not-applicable");
    record.text("protocol.cross_round_transport.requirement",
                required ? "packing-required" : "not-applicable");
    record.integer(
        "protocol.cross_round_transport.aligned_ciphertexts",
        required ? aligned_ciphertexts : 0);
    record.integer(
        "protocol.cross_round_transport.well_formedness_reveals",
        required ? well_formedness_reveals : 0);
    record.text("protocol.cross_round_transport.execution",
                required ? "selected-packed-protocol-path"
                         : "not-applicable");
}

template <fhe::FheBackend Backend, ProtocolKind Kind>
struct ProtocolAdapter;

template <fhe::FheBackend Backend>
struct ProtocolAdapter<Backend, ProtocolKind::Base> {
    using Proof = EncryptedBaseProof<Backend>;
    using PackingSetup = std::monostate;
    using VerifierPackingSetup = std::monostate;
    using ProverTimings = BaseProverTimings;
    using VerifierTimings = BaseVerifierTimings;

    static constexpr std::string_view name = "base";
    static constexpr std::string_view transcript_packing = "none";
    static constexpr std::string_view fixed_round_encoding = "none";
    static constexpr std::string_view transcript_domain =
        "laminate/benchmark/base/v1";

    static Proof prove(const PayloadCircuit &payload,
                       const LayeredCircuit &circuit,
                       const EncryptedTrace<Backend> &trace,
                       const EvaluationSetup<Backend> &setup,
                       const PackingSetup &,
                       const SingleClaim &claim, Transcript &transcript,
                       ProverTimings *timings,
                       ProofTransportPolicy transport,
                       std::function<void()> gkr_complete,
                       RuntimeProgressCallback) {
        (void)gkr_complete;
        if (transport.reserved_mult_depth != 0) {
            throw std::invalid_argument(
                "Base does not support cross-round packing transport");
        }
        return prove_base_reference_profiled<Backend>(
            payload, circuit, trace, setup, claim.point, transcript, *timings);
    }

    static bool verify(const PayloadCircuit &payload,
                       const LayeredCircuit &circuit,
                       std::span<const SlotVector> input,
                       const typename Backend::EvalContext &,
                       const VerifierPackingSetup &,
                       const ClientSetup<Backend> &setup,
                       TraceProvenance provenance, const Digest &trace_id,
                       const SingleClaim &claim, const Proof &proof,
                       Transcript &transcript, VerifierTimings *timings,
                       RuntimeProgressCallback) {
        return verify_base_reference_profiled<Backend>(
            payload, circuit, input, setup, provenance, trace_id, claim,
            proof, transcript, *timings);
    }

    static BaseProofSizeBreakdown measure(const Proof &proof) {
        return measure_proof_size(proof);
    }

    static std::vector<std::uint8_t> encode(const Proof &proof) {
        return encode_canonical(proof);
    }

    static VerifierPackingSetup verifier_setup(const PackingSetup &) {
        return {};
    }

    static const Proof &gkr_proof(const Proof &proof) { return proof; }

    static std::size_t gkr_packing_message_count(const Proof &proof) {
        return measure_proof_size(proof).base_ciphertexts;
    }
};

template <fhe::FheBackend Backend>
struct ProtocolAdapter<Backend, ProtocolKind::Folded> {
    using Proof = LaminateFoldedProof<Backend>;
    using PackingSetup = FoldedSetup;
    using VerifierPackingSetup = FoldedVerifierSetup;
    using ProverTimings = FoldedProverTimings;
    using VerifierTimings = FoldedVerifierTimings;

    static constexpr std::string_view name = "folded";
    static constexpr std::string_view transcript_packing =
        "base17-digits-with-spartan-factored-basefold-packing-proof";
    static constexpr std::string_view fixed_round_encoding =
        "two-fpk-in-one-ciphertext";
    static constexpr std::string_view transcript_domain =
        "laminate/benchmark/folded/v2";

    static Proof prove(const PayloadCircuit &payload,
                       const LayeredCircuit &circuit,
                       const EncryptedTrace<Backend> &trace,
                       const EvaluationSetup<Backend> &setup,
                       const PackingSetup &packing_setup,
                       const SingleClaim &claim, Transcript &transcript,
                       ProverTimings *timings,
                       ProofTransportPolicy transport,
                       std::function<void()> gkr_complete,
                       RuntimeProgressCallback progress) {
        return prove_folded_reference_profiled<Backend>(
            payload, circuit, trace, setup, packing_setup, claim.point,
            transcript, *timings, transport, std::move(gkr_complete),
            std::move(progress));
    }

    static bool verify(const PayloadCircuit &payload,
                       const LayeredCircuit &circuit,
                       std::span<const SlotVector> input,
                       const typename Backend::EvalContext &eval,
                       const VerifierPackingSetup &packing_setup,
                       const ClientSetup<Backend> &setup,
                       TraceProvenance provenance, const Digest &trace_id,
                       const SingleClaim &claim, const Proof &proof,
                       Transcript &transcript, VerifierTimings *timings,
                       RuntimeProgressCallback progress) {
        return verify_folded_profiled<Backend>(
            payload, circuit, input, eval, packing_setup, setup, provenance,
            trace_id, claim, proof, transcript, *timings,
            std::move(progress));
    }

    static FoldedProofSizeBreakdown measure(const Proof &proof) {
        return measure_proof_size<Backend>(proof);
    }

    static std::vector<std::uint8_t> encode(const Proof &proof) {
        return encode_canonical<Backend>(proof);
    }

    static VerifierPackingSetup verifier_setup(
        const PackingSetup &packing_setup) {
        return protocol::verifier_setup(packing_setup);
    }

    static Proof decode(
        const typename Backend::EvalContext &eval,
        std::span<const std::uint8_t> encoded,
        const LayeredCircuit &circuit, const PublicSetup &setup,
        const VerifierPackingSetup &packing_setup) {
        const std::size_t byte_limit = encoded.size();
        return decode_canonical_folded_proof<Backend>(
            eval, encoded, circuit, setup, packing_setup,
            PackedProofDecodeLimits{
                .max_proof_bytes = byte_limit,
                .max_ciphertexts = byte_limit,
                .max_ciphertext_bytes = byte_limit,
                .max_total_ciphertext_bytes = byte_limit,
                .max_collection_elements = byte_limit,
                .max_total_field_elements = byte_limit,
                .max_total_digests = byte_limit,
            });
    }

    static const CommittedFoldedGkrProof &gkr_proof(const Proof &proof) {
        return proof.gkr;
    }

    static std::size_t gkr_packing_message_count(const Proof &proof) {
        return collect_transcript_packing_committed_messages(proof.gkr)
            .size();
    }

};

template <fhe::FheBackend Backend>
struct ProtocolAdapter<Backend, ProtocolKind::Laned> {
    using Proof = LaminateLanedProof<Backend>;
    using PackingSetup = LanedSetup;
    using VerifierPackingSetup = LanedVerifierSetup;
    using ProverTimings = LanedProverTimings;
    using VerifierTimings = LanedVerifierTimings;

    static constexpr std::string_view name = "laned";
    static constexpr std::string_view transcript_packing =
        "base17-digits-with-spartan-factored-basefold-packing-proof";
    static constexpr std::string_view fixed_round_encoding =
        "two-fpk-in-one-ciphertext";
    static constexpr std::string_view transcript_domain =
        "laminate/benchmark/laned/v2";

    static Proof prove(const PayloadCircuit &payload,
                       const LayeredCircuit &circuit,
                       const EncryptedTrace<Backend> &trace,
                       const EvaluationSetup<Backend> &setup,
                       const PackingSetup &packing_setup,
                       const SingleClaim &claim, Transcript &transcript,
                       ProverTimings *timings,
                       ProofTransportPolicy transport,
                       std::function<void()> gkr_complete,
                       RuntimeProgressCallback progress) {
        return prove_laned_reference_profiled<Backend>(
            payload, circuit, trace, setup, packing_setup, claim.point,
            transcript, *timings, transport, std::move(gkr_complete),
            std::move(progress));
    }

    static bool verify(const PayloadCircuit &payload,
                       const LayeredCircuit &circuit,
                       std::span<const SlotVector> input,
                       const typename Backend::EvalContext &eval,
                       const VerifierPackingSetup &packing_setup,
                       const ClientSetup<Backend> &setup,
                       TraceProvenance provenance, const Digest &trace_id,
                       const SingleClaim &claim, const Proof &proof,
                       Transcript &transcript, VerifierTimings *timings,
                       RuntimeProgressCallback progress) {
        return verify_laned_profiled<Backend>(
            payload, circuit, input, eval, packing_setup, setup, provenance,
            trace_id, claim, proof, transcript, *timings,
            std::move(progress));
    }

    static LanedProofSizeBreakdown measure(const Proof &proof) {
        return measure_proof_size<Backend>(proof);
    }

    static std::vector<std::uint8_t> encode(const Proof &proof) {
        return encode_canonical<Backend>(proof);
    }

    static VerifierPackingSetup verifier_setup(
        const PackingSetup &packing_setup) {
        return protocol::verifier_setup(packing_setup);
    }

    static Proof decode(
        const typename Backend::EvalContext &eval,
        std::span<const std::uint8_t> encoded,
        const LayeredCircuit &circuit, const PublicSetup &setup,
        const VerifierPackingSetup &packing_setup) {
        const std::size_t byte_limit = encoded.size();
        return decode_canonical_laned_proof<Backend>(
            eval, encoded, circuit, setup, packing_setup,
            PackedProofDecodeLimits{
                .max_proof_bytes = byte_limit,
                .max_ciphertexts = byte_limit,
                .max_ciphertext_bytes = byte_limit,
                .max_total_ciphertext_bytes = byte_limit,
                .max_collection_elements = byte_limit,
                .max_total_field_elements = byte_limit,
                .max_total_digests = byte_limit,
            });
    }

    static const CommittedLanedGkrProof &gkr_proof(const Proof &proof) {
        return proof.gkr;
    }

    static std::size_t gkr_packing_message_count(const Proof &proof) {
        return collect_transcript_packing_committed_messages(proof.gkr)
            .size();
    }

};

template <fhe::FheBackend Backend> struct SetupArtifacts {
    PublicSetup public_setup;
    typename Backend::Contexts contexts;
    std::shared_ptr<const gates::GateTableProverKey> gate_mle_prover_key;
};

template <fhe::FheBackend Backend, ProtocolKind Kind>
int run(const Options &options, int argc, char **argv,
        std::ostream *result_output) {
    using Adapter = BackendAdapter<Backend>;
    using Protocol = ProtocolAdapter<Backend, Kind>;
    using Counts = typename Adapter::Counts;

    ProtocolProgressJournal progress(options.progress_file);
    progress.phase("circuit_setup.begin");

    const auto [workload, construction_timing] = timed([&] {
        const PayloadShape shape =
            Kind == ProtocolKind::Laned
                ? PayloadShape::laned(options.lanes, options.slots)
                : PayloadShape::wide(options.slots);
        return make_workload(WorkloadSpec{
            options.workload, shape, options.depth, options.width,
            options.seed});
    });
    const auto [circuit, layering_timing] =
        timed([&] { return compile(workload.circuit); });
    const std::optional<ScheduleFormula> schedule_formula = [&] {
        if constexpr (Kind == ProtocolKind::Folded) {
            return std::optional<ScheduleFormula>(
                folded_schedule_formula(circuit));
        }
        if constexpr (Kind == ProtocolKind::Laned) {
            return std::optional<ScheduleFormula>(
                laned_schedule_formula(circuit));
        }
        return std::optional<ScheduleFormula>{};
    }();
    const std::vector<SlotVector> plain_input_layer =
        make_plain_input_layer(circuit, workload.inputs);
    auto [synthetic_trace, trace_timing] = timed([&] {
        return synthesize_trace(workload.circuit, circuit,
                                workload.inputs);
    });
    const Timing validation_timing = timed_void([&] {
        validate_trace(workload.circuit, circuit, synthetic_trace);
    });

    auto [gate_setup, gate_preprocessing_timing] = timed([&] {
        return prepare_gate_mle_setup(
            workload.circuit, circuit, options.gate_mle,
            options.gate_table_max_entries);
    });
    auto [contexts, fhe_setup_timing] =
        timed([&] { return Adapter::create(options); });
    SetupArtifacts<Backend> setup_artifacts{
        std::move(gate_setup.public_setup), std::move(contexts),
        std::move(gate_setup.prover_key)};
    auto [evaluation, plaintext_preprocessing_timing] = timed([&] {
        if constexpr (Kind == ProtocolKind::Base) {
            return make_evaluation_setup<Backend>(
                setup_artifacts.public_setup,
                setup_artifacts.contexts.eval,
                setup_artifacts.gate_mle_prover_key);
        }
        return make_packed_evaluation_setup<Backend>(
            setup_artifacts.public_setup,
            setup_artifacts.contexts.eval,
            setup_artifacts.gate_mle_prover_key);
    });
    auto [packing_setup, packing_setup_timing] = timed([&] {
        if constexpr (Kind == ProtocolKind::Base) {
            return typename Protocol::PackingSetup{};
        } else {
            progress.phase("packing_preprocessing.begin");
            packing::LazyTernaryParameters packing_parameters =
                packing::selected_lazy_ternary_parameters();
            packing_parameters.repetitions =
                options.packing_repetitions;
            if constexpr (Kind == ProtocolKind::Folded) {
                return setup_folded_conservative<Backend>(
                    workload.circuit, circuit,
                    setup_artifacts.public_setup,
                    setup_artifacts.contexts.eval,
                    std::move(packing_parameters));
            } else {
                return setup_laned_conservative<Backend>(
                    workload.circuit, circuit,
                    setup_artifacts.public_setup,
                    setup_artifacts.contexts.eval,
                    std::move(packing_parameters));
            }
        }
    });
    const typename Protocol::VerifierPackingSetup packing_verifier_setup =
        Protocol::verifier_setup(packing_setup);
    const FheEvaluationPlan evaluation_plan = [&] {
        FheEvaluationPlan plan =
            FheEvaluationPlan::without_payload_switches(
                circuit, options.required_proof_depth);
        if constexpr (Kind == ProtocolKind::Folded ||
                      Kind == ProtocolKind::Laned) {
            plan = apply_packed_proof_ingress_schedule(
                circuit, std::move(plan), packing_setup);
            return FheEvaluationPlan::
                packed_payload_with_prompt_switches(
                    circuit, options.fresh_rns_limbs - 1U,
                    plan.proof_ingress_mult_depth_by_layer);
        } else {
            return plan;
        }
    }();
    const Timing setup_timing{
        fhe_setup_timing.wall_ms + gate_preprocessing_timing.wall_ms +
            plaintext_preprocessing_timing.wall_ms +
            packing_setup_timing.wall_ms,
        fhe_setup_timing.cpu_ms + gate_preprocessing_timing.cpu_ms +
            plaintext_preprocessing_timing.cpu_ms +
            packing_setup_timing.cpu_ms};
    const auto client = make_client_setup<Backend>(
        setup_artifacts.public_setup, setup_artifacts.contexts.client);

    EncryptedTrace<Backend> encrypted_trace;
    Timing encryption_timing;
    Timing payload_evaluation_timing;
    Counts encryption_counts{};
    Counts payload_evaluation_counts{};
    Digest packed_session_id{};
    Digest packed_request_digest{};
    if constexpr (Kind == ProtocolKind::Laned) {
        progress.phase("payload_input_encryption.begin");
        Adapter::begin(setup_artifacts.contexts.eval);
        auto encrypted_inputs = timed([&] {
            return encrypt_laned_payload_inputs<Backend>(
                setup_artifacts.contexts.client, workload.circuit,
                workload.inputs);
        });
        encryption_timing = encrypted_inputs.second;
        encryption_counts = Adapter::finish(setup_artifacts.contexts.eval);
        const Digest input_trace_id =
            payload::prevalidated_trace_identity::
                validated_fhe_evaluated_trace_id<Backend>(
                    setup_artifacts.public_setup.circuit_digest,
                    workload.circuit.input_count, encrypted_inputs.first);
        packed_session_id = benchmark_packed_session_id(
            Kind, setup_digest(setup_artifacts.public_setup),
            setup_artifacts.public_setup.circuit_digest, input_trace_id,
            options.seed);
        packed_request_digest = packed_request_commitment<Backend>(
            packed_variant(Kind),
            setup_digest(setup_artifacts.public_setup), packed_session_id,
            setup_artifacts.public_setup.circuit_digest, input_trace_id);

        Adapter::begin(setup_artifacts.contexts.eval);
        progress.phase("payload_evaluation.begin");
        auto evaluated = timed([&] {
            return evaluate_laned_fhe_trace<Backend>(
                setup_artifacts.contexts.eval, workload.circuit, circuit,
                encrypted_inputs.first, evaluation_plan);
        });
        encrypted_trace = std::move(evaluated.first);
        if (encrypted_trace.trace_id != input_trace_id) {
            throw std::logic_error(
                "Laned payload evaluation changed the request trace ID");
        }
        payload_evaluation_timing = evaluated.second;
        payload_evaluation_counts =
            Adapter::finish(setup_artifacts.contexts.eval);
        if (Adapter::decrypt_calls(payload_evaluation_counts) != 0) {
            throw std::logic_error(
                "evaluation role decrypted during payload execution");
        }
    } else if constexpr (Kind == ProtocolKind::Folded) {
        progress.phase("payload_input_encryption.begin");
        Adapter::begin(setup_artifacts.contexts.eval);
        auto encrypted_inputs = timed([&] {
            return encrypt_wide_payload_inputs<Backend>(
                setup_artifacts.contexts.client, workload.circuit,
                workload.inputs);
        });
        encryption_timing = encrypted_inputs.second;
        encryption_counts = Adapter::finish(setup_artifacts.contexts.eval);
        const Digest input_trace_id =
            payload::prevalidated_trace_identity::
                validated_fhe_evaluated_trace_id<Backend>(
                    setup_artifacts.public_setup.circuit_digest,
                    workload.circuit.input_count, encrypted_inputs.first);
        packed_session_id = benchmark_packed_session_id(
            Kind, setup_digest(setup_artifacts.public_setup),
            setup_artifacts.public_setup.circuit_digest, input_trace_id,
            options.seed);
        packed_request_digest = packed_request_commitment<Backend>(
            packed_variant(Kind),
            setup_digest(setup_artifacts.public_setup), packed_session_id,
            setup_artifacts.public_setup.circuit_digest, input_trace_id);

        progress.phase("payload_evaluation.begin");
        Adapter::begin(setup_artifacts.contexts.eval);
        auto evaluated = timed([&] {
            return evaluate_wide_fhe_trace_into<Backend>(
                setup_artifacts.contexts.eval, workload.circuit, circuit,
                encrypted_inputs.first, evaluation_plan,
                InMemoryTraceSink<Backend>{
                    setup_artifacts.contexts.eval});
        });
        encrypted_trace = std::move(evaluated.first);
        if (encrypted_trace.trace_id != input_trace_id) {
            throw std::logic_error(
                "Folded payload evaluation changed the request trace ID");
        }
        payload_evaluation_timing = evaluated.second;
        payload_evaluation_counts =
            Adapter::finish(setup_artifacts.contexts.eval);
        if (Adapter::decrypt_calls(payload_evaluation_counts) != 0) {
            throw std::logic_error(
                "evaluation role decrypted during payload execution");
        }
    } else {
        Adapter::begin(setup_artifacts.contexts.eval);
        auto encrypted = timed([&] {
            return encrypt_compact_synthetic_trace<Backend>(
                setup_artifacts.contexts.eval,
                setup_artifacts.contexts.client, workload.circuit, circuit,
                synthetic_trace, evaluation_plan.trace);
        });
        encrypted_trace = std::move(encrypted.first);
        encryption_timing = encrypted.second;
        encryption_counts = Adapter::finish(setup_artifacts.contexts.eval);
    }

    const std::size_t output_variables =
        Kind == ProtocolKind::Laned
            ? laned_layer_variables(circuit, 0)
            : (std::bit_width(
                   layer_dimensions(circuit.layers.front()).padded_size) -
               1U) +
                  (std::bit_width(circuit.shape.value_width()) - 1U);
    Digest packed_statement_digest{};
    const std::vector<Fpk> output_point = [&] {
        if constexpr (Kind == ProtocolKind::Folded ||
                      Kind == ProtocolKind::Laned) {
            const EncryptedTraceLayer<Backend> &output =
                encrypted_trace.layers.front();
            packed_statement_digest =
                packed_encrypted_statement_digest<Backend>(
                    packed_variant(Kind), packed_request_digest,
                    setup_digest(setup_artifacts.public_setup),
                    packed_session_id,
                    setup_artifacts.public_setup.circuit_digest,
                    encrypted_trace.trace_id, output.dimensions,
                    output.wires);
            Transcript output_randomness(
                "LaminateImpl/PackedDelegationOutputPoint/v1");
            return derive_packed_output_point(
                output_randomness, packed_variant(Kind),
                packed_statement_digest, output_variables);
        }
        Transcript output_randomness("laminate/benchmark/output-point/v1");
        output_randomness.observe(
            "circuit", setup_artifacts.public_setup.circuit_digest);
        output_randomness.observe("seed", options.seed);
        return output_randomness.challenge_vector(output_variables);
    }();
    const SingleClaim output_claim = [&] {
        if constexpr (Kind == ProtocolKind::Laned) {
            return make_packed_laned_claim(
                synthetic_trace.layers.front(), laned_layout(circuit, 0),
                output_point);
        }
        return make_layer_claim(synthetic_trace.layers.front(), output_point);
    }();

    Timing output_decryption_timing;
    Counts output_decryption_counts{};
    Timing output_error_diagnostic_timing;
    Counts output_error_diagnostic_counts{};
    std::size_t encrypted_output_count = 0;
    std::optional<bool> encrypted_outputs_at_q0;
    std::optional<std::uint64_t> output_canonical_error_norm;
    std::optional<std::size_t> output_canonical_error_bits;
    if constexpr (Kind == ProtocolKind::Folded ||
                  Kind == ProtocolKind::Laned) {
        progress.phase("payload_output_decryption.begin");
        Adapter::begin(setup_artifacts.contexts.eval);
        auto decrypted = timed([&] {
            return decrypt_trace_layer<Backend>(
                setup_artifacts.contexts.client, circuit, encrypted_trace,
                0);
        });
        output_decryption_timing = decrypted.second;
        output_decryption_counts =
            Adapter::finish(setup_artifacts.contexts.eval);
        const SingleClaim live_output_claim = [&] {
            if constexpr (Kind == ProtocolKind::Laned) {
                return make_packed_laned_claim(
                    decrypted.first, laned_layout(circuit, 0),
                    output_point);
            }
            return make_layer_claim(decrypted.first, output_point);
        }();
        if (!(live_output_claim == output_claim)) {
            throw std::logic_error(
                "FHE payload output differs from the certified plaintext "
                "reference claim");
        }
        Adapter::begin(setup_artifacts.contexts.eval);
        Stopwatch output_error_diagnostic_timer;
        for (const auto &wire : encrypted_trace.layers.front().wires) {
            if (wire.is_public()) {
                continue;
            }
            ++encrypted_output_count;
            if (Backend::rns_limb_count(
                    setup_artifacts.contexts.eval,
                    wire.ciphertext()) != 1) {
                throw std::logic_error(
                    "packed payload output did not reach the bottom "
                    "ciphertext modulus");
            }
            if constexpr (requires {
                              Backend::data_coefficient_moduli(
                                  setup_artifacts.contexts.eval,
                                  wire.ciphertext());
                          }) {
                const auto live_moduli =
                    Backend::data_coefficient_moduli(
                        setup_artifacts.contexts.eval,
                        wire.ciphertext());
                if (live_moduli.size() != 1 ||
                    live_moduli.front() != kOuterFieldOrder) {
                    throw std::logic_error(
                        "packed payload output did not reach q0=Q");
                }
                encrypted_outputs_at_q0 = true;
            }
            if constexpr (requires {
                              Backend::canonical_error_infinity_norm(
                                  setup_artifacts.contexts.eval,
                                  setup_artifacts.contexts.client,
                                  wire.ciphertext());
                          }) {
                const std::uint64_t norm =
                    Backend::canonical_error_infinity_norm(
                        setup_artifacts.contexts.eval,
                        setup_artifacts.contexts.client,
                        wire.ciphertext());
                output_canonical_error_norm = std::max(
                    output_canonical_error_norm.value_or(0), norm);
            }
        }
        output_error_diagnostic_timing =
            output_error_diagnostic_timer.stop();
        output_error_diagnostic_counts =
            Adapter::finish(setup_artifacts.contexts.eval);
        if (output_canonical_error_norm) {
            output_canonical_error_bits =
                std::bit_width(*output_canonical_error_norm);
            if (*output_canonical_error_bits >
                kPackedOutputCanonicalErrorBits) {
                throw std::runtime_error(
                    "packed payload output exceeds the 10-bit honest "
                    "canonical-error target");
            }
        }
        if constexpr (Adapter::has_invariant_noise) {
            if (encrypted_output_count != 0 &&
                !output_canonical_error_norm) {
                throw std::logic_error(
                    "packed SEAL output has no canonical-error "
                    "measurement");
            }
        }
    }

    using Proof = typename Protocol::Proof;
    std::optional<Proof> retained_proof;
    Counts prove_counts;
    Counts verify_counts;
    std::vector<double> prove_wall;
    std::vector<double> prove_cpu;
    std::vector<double> serialize_wall;
    std::vector<double> serialize_cpu;
    std::vector<double> decode_wall;
    std::vector<double> decode_cpu;
    std::vector<double> verify_wall;
    std::vector<double> verify_cpu;
    std::vector<double> packed_message_verification_wall;
    std::vector<double> packed_message_verification_cpu;
    std::vector<double> prove_gate_opening_wall;
    std::vector<double> prove_gate_opening_cpu;
    std::vector<double> verify_gate_opening_wall;
    std::vector<double> verify_gate_opening_cpu;
    std::vector<double> plaintext_verify_wall;
    std::vector<double> plaintext_verify_cpu;
    std::vector<double> transcript_packing_wall;
    std::vector<double> transcript_packing_cpu;
    std::optional<packing::LazyTernaryThresholdAssessment>
        transcript_packing_threshold;
    Counts gkr_prove_counts{};
    bool gkr_prove_counts_recorded = false;
    const std::size_t reduction_count = circuit.layers.size() - 1;
    std::vector<std::vector<double>> prove_layer_wall(reduction_count);
    std::vector<std::vector<double>> prove_layer_cpu(reduction_count);
    std::vector<std::vector<double>> verify_layer_wall(reduction_count);
    std::vector<std::vector<double>> verify_layer_cpu(reduction_count);
    std::size_t encoded_bytes = 0;
    std::size_t completed_iterations = 0;
    bool accepted = true;
    std::optional<std::string> rejection_stage;
    std::optional<std::string> rejection_message;

    for (std::size_t iteration = 0; iteration < options.iterations;
         ++iteration) {
        gkr_prove_counts_recorded = false;
        progress.phase("proof.begin");
        Adapter::begin(setup_artifacts.contexts.eval);
        Stopwatch prove_timer;
        Transcript prover_transcript(Protocol::transcript_domain);
        typename Protocol::ProverTimings prover_breakdown;
        Proof proof = Protocol::prove(
            workload.circuit, circuit, encrypted_trace, evaluation,
            packing_setup, output_claim, prover_transcript,
            &prover_breakdown,
            ProofTransportPolicy{
                Kind == ProtocolKind::Base
                    ? std::size_t{0}
                    : kPackingReservedMultDepth},
            [&] {
                gkr_prove_counts =
                    Adapter::snapshot(setup_artifacts.contexts.eval);
                gkr_prove_counts_recorded = true;
                progress.phase("proof.gkr.complete");
                if constexpr (Kind != ProtocolKind::Base) {
                    progress.phase("proof.transcript_packing.begin");
                }
            },
            progress.callback());
        if constexpr (Kind != ProtocolKind::Base) {
            progress.phase("proof.transcript_packing.complete");
        }
        const Timing prove_timing = prove_timer.stop();
        prove_counts = Adapter::finish(setup_artifacts.contexts.eval);
        if (Adapter::decrypt_calls(prove_counts) != 0) {
            throw std::logic_error("evaluation role decrypted during proving");
        }
        prove_wall.push_back(prove_timing.wall_ms);
        prove_cpu.push_back(prove_timing.cpu_ms);
        prove_gate_opening_wall.push_back(
            prover_breakdown.gate_mle_opening_wall_ms);
        prove_gate_opening_cpu.push_back(
            prover_breakdown.gate_mle_opening_cpu_ms);
        if constexpr (Kind == ProtocolKind::Base) {
            transcript_packing_wall.push_back(0);
            transcript_packing_cpu.push_back(0);
        } else {
            if (!gkr_prove_counts_recorded) {
                throw std::logic_error(
                    "packed prover did not report its GKR boundary");
            }
            transcript_packing_wall.push_back(
                prover_breakdown.transcript_packing_wall_ms);
            transcript_packing_cpu.push_back(
                prover_breakdown.transcript_packing_cpu_ms);
        }
        if (prover_breakdown.layers.size() != reduction_count) {
            throw std::logic_error("prover layer timing count disagrees");
        }
        for (std::size_t layer = 0; layer < reduction_count; ++layer) {
            const BaseLayerTiming &timing = prover_breakdown.layers[layer];
            if (timing.layer != layer ||
                timing.kind != layer_kind(circuit.layers[layer])) {
                throw std::logic_error("prover layer timing identity drifted");
            }
            prove_layer_wall[layer].push_back(timing.wall_ms);
            prove_layer_cpu[layer].push_back(timing.cpu_ms);
        }

        Stopwatch serialize_timer;
        progress.phase("proof_serialization.begin");
        const std::vector<std::uint8_t> encoded = Protocol::encode(proof);
        const Timing serialize_timing = serialize_timer.stop();
        if (encoded_bytes != 0 && encoded_bytes != encoded.size()) {
            throw std::runtime_error(
                "canonical proof size changed across deterministic iterations");
        }
        encoded_bytes = encoded.size();
        serialize_wall.push_back(serialize_timing.wall_ms);
        serialize_cpu.push_back(serialize_timing.cpu_ms);

        if constexpr (Kind == ProtocolKind::Base) {
            decode_wall.push_back(0.0);
            decode_cpu.push_back(0.0);
        } else {
            progress.phase("proof_decoding.begin");
            Stopwatch decode_timer;
            Proof decoded = Protocol::decode(
                setup_artifacts.contexts.eval, encoded, circuit,
                client.public_setup, packing_verifier_setup);
            const Timing decode_timing = decode_timer.stop();
            decode_wall.push_back(decode_timing.wall_ms);
            decode_cpu.push_back(decode_timing.cpu_ms);

            proof = std::move(decoded);
        }

        Adapter::begin(setup_artifacts.contexts.eval);
        progress.phase("verification.begin");
        Stopwatch verify_timer;
        Transcript verifier_transcript(Protocol::transcript_domain);
        typename Protocol::VerifierTimings verifier_breakdown;
        const bool iteration_accepted = Protocol::verify(
            workload.circuit, circuit, plain_input_layer,
            setup_artifacts.contexts.eval, packing_verifier_setup, client,
            encrypted_trace.provenance, encrypted_trace.trace_id,
            output_claim, proof, verifier_transcript, &verifier_breakdown,
            progress.callback());
        const Timing verify_timing = verify_timer.stop();
        verify_counts = Adapter::finish(setup_artifacts.contexts.eval);
        verify_wall.push_back(verify_timing.wall_ms);
        verify_cpu.push_back(verify_timing.cpu_ms);
        if constexpr (Kind != ProtocolKind::Base) {
            const auto &assessment =
                verifier_breakdown.transcript_packing_threshold;
            if (assessment.checks_performed) {
                if (transcript_packing_threshold &&
                    *transcript_packing_threshold != assessment) {
                    throw std::logic_error(
                        "transcript-packing threshold assessment changed "
                        "across deterministic iterations");
                }
                transcript_packing_threshold = assessment;
            }
        }
        if (verifier_breakdown.layers.size() > reduction_count ||
            (iteration_accepted &&
             verifier_breakdown.layers.size() != reduction_count)) {
            throw std::logic_error("verifier layer timing count disagrees");
        }
        for (std::size_t layer = 0;
             layer < verifier_breakdown.layers.size(); ++layer) {
            const BaseLayerTiming &timing = verifier_breakdown.layers[layer];
            if (timing.layer != layer ||
                timing.kind != layer_kind(circuit.layers[layer])) {
                throw std::logic_error(
                    "verifier layer timing identity drifted");
            }
            verify_layer_wall[layer].push_back(timing.wall_ms);
            verify_layer_cpu[layer].push_back(timing.cpu_ms);
        }
        packed_message_verification_wall.push_back(
            verifier_breakdown.packed_message_verification_wall_ms);
        packed_message_verification_cpu.push_back(
            verifier_breakdown.packed_message_verification_cpu_ms);
        verify_gate_opening_wall.push_back(
            verifier_breakdown.gate_mle_opening_wall_ms);
        verify_gate_opening_cpu.push_back(
            verifier_breakdown.gate_mle_opening_cpu_ms);
        plaintext_verify_wall.push_back(std::max(
            0.0, verify_timing.wall_ms -
                     verifier_breakdown.packed_message_verification_wall_ms -
                     verifier_breakdown.gate_mle_opening_wall_ms));
        plaintext_verify_cpu.push_back(std::max(
            0.0, verify_timing.cpu_ms -
                     verifier_breakdown.packed_message_verification_cpu_ms -
                     verifier_breakdown.gate_mle_opening_cpu_ms));

        if (!iteration_accepted) {
            std::string iteration_rejection_stage = "gkr-replay";
            std::optional<packing::LazyTernaryThresholdAssessment>
                rejection_threshold;
            if constexpr (Kind != ProtocolKind::Base) {
                const bool gkr_structure_valid = [&] {
                    if constexpr (Kind == ProtocolKind::Folded) {
                        return gkr::folded_detail::validate_structure(
                            proof.gkr, encrypted_trace.provenance,
                            encrypted_trace.trace_id,
                            client.public_setup, circuit);
                    } else {
                        return gkr::laned_detail::validate_structure(
                            proof.gkr, encrypted_trace.provenance,
                            encrypted_trace.trace_id,
                            client.public_setup, circuit);
                    }
                }();
                if (!gkr_structure_valid) {
                    iteration_rejection_stage =
                        "committed-gkr-structure";
                } else {
                    try {
                        Transcript diagnostic_transcript(
                            Protocol::transcript_domain);
                        constexpr auto variant = Kind == ProtocolKind::Folded
                            ? ProtocolVariant::LaminateFolded
                            : ProtocolVariant::LaminateLaned;
                        const auto public_replay = protocol::detail::
                            replay_packed_gkr_transcript<variant, Backend>(
                                circuit, client.public_setup, proof.gkr,
                                output_claim.point, diagnostic_transcript);
                        if (!public_replay) {
                            iteration_rejection_stage = "gkr-public-replay";
                        } else {
                            protocol::detail::bind_committed_gkr_for_packing(
                                proof.gkr, diagnostic_transcript);
                            const auto messages =
                                collect_transcript_packing_committed_messages(
                                    proof.gkr);
                            const auto packed =
                                protocol::detail::
                                    verify_transcript_packing<Backend>(
                                        setup_artifacts.contexts.eval,
                                        client.context,
                                        packing_verifier_setup.transcript_packing,
                                        messages, proof.transcript_packing,
                                        diagnostic_transcript);
                            if (!packed.spartan_proof) {
                                iteration_rejection_stage =
                                    "transcript-packing-spartan";
                            } else if (!packed.threshold_checks) {
                                iteration_rejection_stage =
                                    "transcript-packing-threshold";
                                rejection_threshold =
                                    packed.threshold_assessment;
                            } else if (packed.logical_messages.empty()) {
                                iteration_rejection_stage =
                                    "transcript-unpack";
                            }
                        }
                    } catch (const std::exception &error) {
                        iteration_rejection_stage =
                            "transcript-packing-exception:" +
                            std::string(error.what());
                    }
                }
            }
            std::string message =
                "honest protocol proof rejected at " +
                iteration_rejection_stage;
            if (output_canonical_error_norm) {
                message += "; payload output canonical error norm=" +
                           std::to_string(
                               *output_canonical_error_norm);
            }
            if (rejection_threshold &&
                rejection_threshold->checks_performed) {
                transcript_packing_threshold = rejection_threshold;
                message += "; configured threshold=" +
                           std::to_string(
                               rejection_threshold->configured_threshold) +
                           "; maximum observed norm=" +
                           std::to_string(
                               rejection_threshold->maximum_observed_norm) +
                           "; failing reveal count=" +
                           std::to_string(
                               rejection_threshold->failing_reveal_count) +
                           "; first failing reveal index=" +
                           (rejection_threshold
                                    ->first_failing_reveal_index
                                ? std::to_string(*rejection_threshold
                                                     ->first_failing_reveal_index)
                                : "none");
            }
            rejection_stage = std::move(iteration_rejection_stage);
            rejection_message = std::move(message);
        }
        accepted = accepted && iteration_accepted;
        retained_proof = std::move(proof);
        ++completed_iterations;
        if (!iteration_accepted) {
            break;
        }
    }
    if (!retained_proof) {
        throw std::logic_error("benchmark produced no proof");
    }
    progress.phase("measurement.begin");

    const auto proof_size = Protocol::measure(*retained_proof);
    if (proof_size.total_bytes != encoded_bytes) {
        throw std::logic_error("proof measurement disagrees with encoding");
    }
    if (schedule_formula &&
        (schedule_formula->operations.logical_rounds !=
             proof_size.logical_round_messages ||
         schedule_formula->operations.aligned_round_ciphertexts !=
             Protocol::gkr_packing_message_count(*retained_proof))) {
        throw std::logic_error(
            "schedule formula disagrees with physical proof structure");
    }
    const CiphertextMeasurements<Backend> proof_ciphertexts =
        measure_proof_ciphertexts<Backend>(setup_artifacts.contexts.eval,
                                           *retained_proof);
    const CiphertextMeasurements<Backend> trace_ciphertexts =
        measure_trace_ciphertexts(setup_artifacts.contexts.eval,
                                  encrypted_trace);
    if (proof_ciphertexts.bytes.size() != proof_size.base_ciphertexts) {
        throw std::logic_error("physical proof ciphertext count disagrees");
    }
    constexpr bool uses_transcript_packing =
        Kind != ProtocolKind::Base;
    const std::size_t packing_repetitions = [&] {
        if constexpr (uses_transcript_packing) {
            return packing_setup.transcript_packing.parameters.repetitions;
        }
        return std::size_t{0};
    }();
    const bool selected_packing_repetitions =
        !uses_transcript_packing ||
        packing_repetitions == kPackingWellFormednessRepetitions;
    const std::size_t aligned_packing_ciphertexts =
        uses_transcript_packing
            ? Protocol::gkr_packing_message_count(*retained_proof)
            : 0;
    if constexpr (uses_transcript_packing) {
        if (packing_repetitions == 0 ||
            aligned_packing_ciphertexts == 0) {
            throw std::logic_error(
                "packed proof has an empty transcript-packing shape");
        }
    }

    MeasuredNoise proof_measured_noise;
    MeasuredNoise trace_measured_noise;
    if constexpr (Adapter::has_invariant_noise) {
        const auto &noise_client_context =
            setup_artifacts.contexts.client;
        for_each_proof_ciphertext<Backend>(
            *retained_proof,
            [&](const auto &ciphertext, const std::string &checkpoint) {
                proof_measured_noise.observe(
                    Backend::invariant_noise_budget(
                        noise_client_context, ciphertext),
                    checkpoint);
            });
        for (std::size_t layer = 0; layer < encrypted_trace.layers.size();
             ++layer) {
            for (std::size_t wire = 0;
                 wire < encrypted_trace.layers[layer].wires.size(); ++wire) {
                const fhe::FheValue<Backend> &value =
                    encrypted_trace.layers[layer].wires[wire];
                if (value.is_public()) {
                    continue;
                }
                trace_measured_noise.observe(
                    Backend::invariant_noise_budget(
                        noise_client_context, value.ciphertext()),
                    "layer/" + std::to_string(layer) + "/wire/" +
                        std::to_string(wire));
            }
        }
        if (accepted && proof_measured_noise.minimum <= 0) {
            throw std::runtime_error(
                "proof contains a ciphertext with exhausted measured noise");
        }
    }

    const PayloadStats payload_stats = analyze(workload.circuit);
    std::vector<std::string> layer_kinds;
    std::vector<std::size_t> logical_widths;
    std::vector<std::size_t> padded_widths;
    std::vector<std::size_t> payload_widths;
    std::vector<std::size_t> forward_widths;
    std::vector<std::size_t> padding_widths;
    std::vector<std::size_t> packed_ciphertext_widths;
    std::vector<std::size_t> rounds;
    std::size_t trace_value_count = 0;
    std::size_t trace_ciphertext_count = 0;
    std::size_t trace_public_value_count = 0;
    std::size_t trace_public_zero_count = 0;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const LayerDimensions &dimensions =
            layer_dimensions(circuit.layers[layer]);
        layer_kinds.push_back(
            layer_kind_name(layer_kind(circuit.layers[layer])));
        logical_widths.push_back(dimensions.logical_size);
        padded_widths.push_back(dimensions.padded_size);
        payload_widths.push_back(dimensions.payload_size);
        forward_widths.push_back(dimensions.forward_size);
        padding_widths.push_back(dimensions.padding_size());
        if constexpr (Kind == ProtocolKind::Laned) {
            packed_ciphertext_widths.push_back(
                laned_layout(circuit, layer).padded_ciphertext_count);
        }
        for (const fhe::FheValue<Backend> &value :
             encrypted_trace.layers[layer].wires) {
            ++trace_value_count;
            if (value.is_encrypted()) {
                ++trace_ciphertext_count;
            } else {
                ++trace_public_value_count;
                if (value.is_public_zero()) {
                    ++trace_public_zero_count;
                }
            }
        }
        rounds.push_back(
            layer + 1 == circuit.layers.size()
                ? 0
                : std::visit(
                      [](const auto &reduction) {
                          return reduction.rounds.size();
                      },
                      Protocol::gkr_proof(*retained_proof)
                          .reductions[layer]));
    }
    std::vector<std::size_t> rotation_steps;
    for (const Gate &gate : workload.circuit.gates) {
        if (gate.op == GateOp::Rotate) {
            rotation_steps.push_back(gate.parameter);
        }
    }
    std::sort(rotation_steps.begin(), rotation_steps.end());
    rotation_steps.erase(
        std::unique(rotation_steps.begin(), rotation_steps.end()),
        rotation_steps.end());

    const auto rns_limbs = [](std::span<const std::size_t> depths) {
        std::vector<std::size_t> result;
        result.reserve(depths.size());
        for (const std::size_t depth : depths) {
            if (depth == std::numeric_limits<std::size_t>::max()) {
                throw std::overflow_error(
                    "benchmark RNS depth does not fit a limb count");
            }
            result.push_back(depth + 1U);
        }
        return result;
    };
    const std::vector<std::size_t> natural_rns_limbs_by_layer =
        rns_limbs(evaluation_plan.trace.required_mult_depth_by_layer);
    const std::vector<std::size_t> proof_ingress_rns_limbs_by_layer =
        rns_limbs(evaluation_plan.proof_ingress_mult_depth_by_layer);

    const Samples prove_wall_summary = summarize(prove_wall);
    const Samples serialize_wall_summary = summarize(serialize_wall);
    const Samples decode_wall_summary = summarize(decode_wall);
    double gkr_prove_wall_ms = 0;
    double gkr_prove_cpu_ms = 0;
    for (std::size_t layer = 0; layer < reduction_count; ++layer) {
        gkr_prove_wall_ms += summarize(prove_layer_wall[layer]).mean;
        gkr_prove_cpu_ms += summarize(prove_layer_cpu[layer]).mean;
    }
    const Record record(result_output);
    record.text("format", "laminate-benchmark-v9");
    record.text("classification.trace_source",
                Kind != ProtocolKind::Base ? "fhe-evaluated"
                                           : "synthetic-trace");
    record.text("classification.backend",
                std::is_same_v<Backend, MockBackend> ? "mock" : "seal-bgv");
    record.text("classification.protocol", std::string(Protocol::name));
    record.text("protocol.gkr_claim_transition",
                std::string(gkr::kGkrClaimTransition));
    record.text("protocol.gkr_multiplication",
                std::string(gkr::kGkrMultiplicationReduction));
    if constexpr (Kind != ProtocolKind::Base) {
        record.text("protocol.fiat_shamir",
                    std::string(protocol::kPackedFiatShamirSchedule));
    }
    record.text("classification.payload_shape",
                Kind == ProtocolKind::Laned ? "laned" : "wide");
    record.text(
        "classification.process_topology",
        "single-process-in-memory-client-and-server-roles");
    record.text(
        "classification.transport",
        Kind == ProtocolKind::Base
            ? "canonical-proof-encoding-only-no-wire-round-trip"
            : "one-round-compatible-encrypted-statement;canonical-packed-"
              "proof-bounded-outer-decode-and-direct-verification");
    record.text(
        "classification.verifier_setup",
        Kind == ProtocolKind::Base
            ? "base-client-setup"
            : "compact-packed-verifier-setup-no-prover-preprocessing");
    record.text(
        "classification.storage",
        Kind == ProtocolKind::Base
            ? "resident-synthetic-encrypted-trace"
            : "resident-fhe-evaluated-trace-and-resident-transcript-packing");
    record.text("classification.resource_admission", "none");
    record.text("classification.threading", "single-threaded-executable");
    record.text(
        "classification.server_secret_key_boundary",
        "evaluation-context-used-for-payload-and-proving-no-decrypt-calls");
    emit_gate_mle_setup(
        record, setup_artifacts.gate_mle_prover_key,
        options.gate_table_max_entries);
    record.text("classification.transcript_packing",
                std::string(Protocol::transcript_packing));
    record.text(
        "classification.transcript_packing_integrity",
        !uses_transcript_packing
            ? "not-applicable"
            : selected_packing_repetitions
                  ? "selected-120-repetition-profile"
                  : "diagnostic-nonselected-repetitions-no-security-claim");
    record.text("classification.fixed_round_encoding",
                std::string(Protocol::fixed_round_encoding));
    record.text(
        "classification.protocol_completeness",
        uses_transcript_packing
            ? "binding-succinct-spartan-factored-basefold-packing"
            : "complete-raw-base-proof");
    record.text(
        "classification.security",
        uses_transcript_packing
            ? selected_packing_repetitions
                  ? "poseidon-ciphertext-commitment-r1cs;spartan-piop;"
                    "factored-matrix-commitment;basefold-blake2b320;"
                    "sha256-bcs16"
                  : "diagnostic-nonselected-well-formedness-repetitions;"
                    "no-integrity-security-claim"
            : options.security);
    record.text("classification.fhe_parameter_security", options.security);
    record.text("classification.result_kind", "measured");
    record.text("classification.timing_validity",
                accepted ? "valid-performance-sample"
                         : "valid-rejected-diagnostic-sample");
    record.text("classification.run_tier", options.run_tier);
    record.integer("benchmark.iterations", options.iterations);
    record.integer("benchmark.completed_iterations", completed_iterations);
    emit_benchmark_provenance(record, argc, argv);
    record.integer("environment.thread_count", 1);

    record.text("workload.name", std::string(workload_name(options.workload)));
    record.integer("workload.seed", options.seed);
    record.integer("workload.requested_depth", options.depth);
    record.integer("workload.requested_width", options.width);
    record.integer("workload.input_count", workload.circuit.input_count);
    record.integer("workload.output_count", workload.circuit.outputs.size());
    record.integer("workload.fhe_operations", workload.circuit.gates.size());
    record.integer("workload.gates.add", payload_stats.add_gates);
    record.integer("workload.gates.add_plain", payload_stats.add_plain_gates);
    record.integer("workload.gates.mul", payload_stats.mul_gates);
    record.integer("workload.gates.mul_plain", payload_stats.mul_plain_gates);
    record.integer("workload.gates.rotate", payload_stats.rotate_gates);
    record.integer("workload.depth.ct_ct",
                   payload_stats.ct_ct_multiplicative_depth);
    record.integer("workload.depth.fhe_half_levels",
                   payload_stats.fhe_half_depth);
    record.integer("workload.depth.alternating",
                   payload_stats.alternating_multiplicative_depth);
    record.text("workload.rotation_steps",
                rotation_steps.empty() ? "none" : join(rotation_steps));

    record.integer("parameters.t", kBaseFieldOrder);
    record.integer("parameters.transcript_packing_repetitions",
                   packing_repetitions);
    record.integer("parameters.selected_transcript_packing_repetitions",
                   uses_transcript_packing
                       ? kPackingWellFormednessRepetitions
                       : 0);
    record.integer("parameters.extension_degree", kExtensionDegree);
    record.integer("parameters.N", options.slots);
    record.integer("parameters.lane_count_B",
                   Kind == ProtocolKind::Laned ? options.lanes : 0);
    record.integer("parameters.chunks_per_ciphertext",
                   Kind == ProtocolKind::Laned
                       ? options.slots / options.lanes
                       : 0);
    record.integer("parameters.target_security_bits_metadata",
                   kTargetSecurityBits);
    record.integer("parameters.required_proof_depth",
                   options.required_proof_depth);
    record.text(
        "parameters.modulus_chain_status",
        options.modulus_chain_profile);
    record.text(
        "parameters.payload_mod_switch_policy",
        Kind != ProtocolKind::Base
            ? "prompt-smallest-level-after-ctct-then-bottom-output"
            : "none-synthetic-trace");
    record.text("parameters.payload_mod_switches_after_layer",
                join(evaluation_plan.modulus_switches_after_layer));
    if constexpr (Kind != ProtocolKind::Base) {
        record.integer("parameters.payload_output_rns_limbs_target", 1);
        record.integer("parameters.payload_output_error_target_bits",
                       kPackedOutputCanonicalErrorBits);
        record.text(
            "parameters.proof_ingress_selection",
            std::string(
                packing_setup.conservative_proof_ingress_schedule->policy()));
        record.text(
            "parameters.proof_ingress_schedule_digest",
            digest_hex(
                packing_setup.conservative_proof_ingress_schedule->digest()));
    }
    record.text("parameters.natural_payload_rns_limbs_by_layer",
                join(natural_rns_limbs_by_layer));
    record.text("parameters.proof_ingress_rns_limbs_by_layer",
                join(proof_ingress_rns_limbs_by_layer));
    record.integer("parameters.transport_reserved_mult_depth",
                   Kind == ProtocolKind::Base
                       ? 0
                       : kPackingReservedMultDepth);
    record.integer("parameters.fresh_rns_limbs", options.fresh_rns_limbs);
    Adapter::emit_parameters(record, options,
                             setup_artifacts.contexts.eval);
    record.text("parameters.relinearization_policy",
                "lazy-once-per-product-message-limb");

    record.integer("circuit.layer_count", circuit.layers.size());
    record.integer("circuit.proof_multiplication_depth",
                   circuit.proof_multiplication_depth);
    record.text("circuit.layer_kinds", join(layer_kinds));
    record.text("circuit.logical_widths", join(logical_widths));
    record.text("circuit.padded_widths", join(padded_widths));
    record.text("circuit.payload_widths", join(payload_widths));
    record.text("circuit.forward_widths", join(forward_widths));
    record.text("circuit.padding_widths", join(padding_widths));
    record.text("circuit.packed_ciphertext_widths",
                Kind == ProtocolKind::Laned
                    ? join(packed_ciphertext_widths)
                    : "not-applicable");
    record.text("protocol.rounds_by_layer", join(rounds));
    record.integer("protocol.logical_rounds",
                   proof_size.logical_round_messages);
    emit_cross_round_packing_requirement(
        record, uses_transcript_packing, aligned_packing_ciphertexts,
        packing_repetitions);
    record.integer("trace.values", trace_value_count);
    record.integer("trace.ciphertexts", trace_ciphertext_count);
    record.integer("trace.public_values", trace_public_value_count);
    record.integer("trace.public_zero_values", trace_public_zero_count);
    record.integer("trace.public_nonzero_values",
                   trace_public_value_count - trace_public_zero_count);
    record.integer("trace.original_b_periodic_ciphertexts",
                   Kind == ProtocolKind::Laned ? trace_ciphertext_count : 0);
    record.integer("trace.original_b_periodic_values",
                   Kind == ProtocolKind::Laned ? trace_value_count : 0);
    record.text("trace.circuit_id",
                digest_hex(setup_artifacts.public_setup.circuit_digest));
    record.text("trace.trace_id", digest_hex(encrypted_trace.trace_id));
    record.text("setup.setup_id",
                digest_hex(setup_digest(setup_artifacts.public_setup)));
    record.text(
        "protocol.output_point_derivation",
        Kind == ProtocolKind::Base
            ? "benchmark-seed-and-circuit"
            : "complete-encrypted-request-and-output-statement");
    record.text("protocol.session_id",
                Kind == ProtocolKind::Base
                    ? "not-applicable"
                    : digest_hex(packed_session_id));
    record.text("protocol.request_commitment",
                Kind == ProtocolKind::Base
                    ? "not-applicable"
                    : digest_hex(packed_request_digest));
    record.text("protocol.encrypted_statement_digest",
                Kind == ProtocolKind::Base
                    ? "not-applicable"
                    : digest_hex(packed_statement_digest));
    if constexpr (requires(const typename Backend::EvalContext &context) {
                      Backend::plaintext_preprocessing_stats(context);
                  }) {
        const auto stats = Backend::plaintext_preprocessing_stats(
            setup_artifacts.contexts.eval);
        record.text("setup.plaintext_preprocessing.status",
                    Kind == ProtocolKind::Base ? "not-requested"
                                               : "fixed-round-masks-ready");
        record.integer("setup.plaintext_preprocessing.logical_plaintexts",
                       stats.logical_plaintexts);
        record.integer(
            "setup.plaintext_preprocessing.level_representations",
            stats.level_representations);
        record.integer(
            "setup.plaintext_preprocessing.ntt_coefficient_bytes",
            stats.ntt_coefficient_bytes);
    } else {
        record.text("setup.plaintext_preprocessing.status",
                    "backend-has-no-explicit-ntt-cache");
    }

    emit_timing(record, "circuit_construction", construction_timing);
    emit_timing(record, "circuit_layering", layering_timing);
    emit_timing(record, "plaintext_reference_evaluation", trace_timing);
    emit_timing(record, "plaintext_reference_validation", validation_timing);
    emit_timing(record, "setup", setup_timing);
    emit_timing(record, "fhe_setup", fhe_setup_timing);
    emit_timing(record, "gate_mle_preprocessing",
                gate_preprocessing_timing);
    emit_timing(record, "plaintext_preprocessing",
                plaintext_preprocessing_timing);
    emit_timing(record, "packing_preprocessing", packing_setup_timing);
    emit_timing(record,
                Kind != ProtocolKind::Base ? "payload_input_encryption"
                                           : "trace_encryption",
                encryption_timing);
    emit_timing(record, "payload_fhe_evaluation",
                payload_evaluation_timing);
    emit_timing(record, "payload_output_decryption",
                output_decryption_timing);
    emit_timing(record, "payload_output_error_diagnostic",
                output_error_diagnostic_timing);
    record.text(
        "timing.payload_output_error_diagnostic.scope",
        Kind == ProtocolKind::Base
            ? "not-applicable"
            : "secret-key-assisted-audit-excluded-from-online-client-time");
    record.text("timing.witness_packing.accounting",
                Kind == ProtocolKind::Laned
                    ? "included-in-layer-proving-not-separately-instrumented"
                    : "not-applicable");
    emit_samples(record, "timing.transcript_packing.wall_ms",
                 transcript_packing_wall);
    emit_samples(record, "timing.transcript_packing.cpu_ms",
                 transcript_packing_cpu);
    record.text("timing.transcript_packing.scope",
                Kind == ProtocolKind::Base
                    ? "not-applicable"
                    : selected_packing_repetitions
                          ? "selected-base17-packing-stage"
                          : "diagnostic-nonselected-repetition-packing-stage");
    record.real("timing.gkr_proving.wall_ms", gkr_prove_wall_ms);
    record.real("timing.gkr_proving.cpu_ms", gkr_prove_cpu_ms);
    record.text("timing.gkr_proving.scope",
                "sum-of-profiled-encrypted-layer-reductions");
    record.text("timing.fixed_round_encoding",
                Kind == ProtocolKind::Base
                    ? "not-applicable"
                    : "included-in-per-layer-proving");
    emit_samples(record, "timing.gate_mle_opening.prove.wall_ms",
                 prove_gate_opening_wall);
    emit_samples(record, "timing.gate_mle_opening.prove.cpu_ms",
                 prove_gate_opening_cpu);
    emit_samples(record, "timing.gate_mle_opening.verify.wall_ms",
                 verify_gate_opening_wall);
    emit_samples(record, "timing.gate_mle_opening.verify.cpu_ms",
                 verify_gate_opening_cpu);
    emit_samples(record, "timing.prove.wall_ms", prove_wall);
    emit_samples(record, "timing.prove.cpu_ms", prove_cpu);
    emit_samples(record, "timing.proof_serialization.wall_ms",
                 serialize_wall);
    emit_samples(record, "timing.proof_serialization.cpu_ms", serialize_cpu);
    emit_samples(record, "timing.proof_decoding.wall_ms", decode_wall);
    emit_samples(record, "timing.proof_decoding.cpu_ms", decode_cpu);
    record.text(
        "timing.proof_decoding.scope",
        Kind == ProtocolKind::Base
            ? "not-applicable"
            : "bounded-setup-shaped-outer-decode-included-in-online-client-"
              "time;opaque-basefold-openings-parsed-once-by-verification");
    emit_samples(record, "timing.verify_including_decryption.wall_ms",
                 verify_wall);
    emit_samples(record, "timing.verify_including_decryption.cpu_ms",
                 verify_cpu);
    emit_samples(record, "timing.client_packed_message_verification.wall_ms",
                 packed_message_verification_wall);
    emit_samples(record, "timing.client_packed_message_verification.cpu_ms",
                 packed_message_verification_cpu);
    record.text(
        "timing.client_packed_message_verification.scope",
        Kind == ProtocolKind::Base
            ? "direct-base-message-decryption-and-extension-unpack"
            : "complete-transcript-packing-proof-verification-and-message-"
              "recovery");
    if constexpr (Kind != ProtocolKind::Base) {
        if (!transcript_packing_threshold ||
            !transcript_packing_threshold->checks_performed) {
            if (accepted) {
                throw std::logic_error(
                    "accepted packed proof has no threshold assessment");
            }
            record.text(
                "verification.transcript_packing_threshold.result",
                "NOT-REACHED-BEFORE-REJECTION");
        } else {
            const auto &assessment = *transcript_packing_threshold;
            record.integer(
                "verification.transcript_packing_threshold.configured",
                assessment.configured_threshold);
            record.integer(
                "verification.transcript_packing_threshold.maximum_observed_norm",
                assessment.maximum_observed_norm);
            record.integer(
                "verification.transcript_packing_threshold.expected_reveals",
                assessment.expected_reveal_count);
            record.integer(
                "verification.transcript_packing_threshold.observed_reveals",
                assessment.observed_reveal_count);
            record.integer(
                "verification.transcript_packing_threshold.checked_reveals",
                assessment.checked_reveal_count);
            record.integer(
                "verification.transcript_packing_threshold.failing_reveals",
                assessment.failing_reveal_count);
            record.text(
                "verification.transcript_packing_threshold.first_failing_reveal_index",
                assessment.first_failing_reveal_index
                    ? std::to_string(
                          *assessment.first_failing_reveal_index)
                    : "none");
            record.text(
                "verification.transcript_packing_threshold.result",
                assessment.accepts() ? "PASS" : "FAIL");
        }
    }
    emit_samples(record, "timing.plaintext_verification.wall_ms",
                 plaintext_verify_wall);
    emit_samples(record, "timing.plaintext_verification.cpu_ms",
                 plaintext_verify_cpu);
    for (std::size_t layer = 0; layer < reduction_count; ++layer) {
        const std::string prove_prefix =
            "timing.prove.layer." + std::to_string(layer);
        const std::string verify_prefix =
            "timing.verify.layer." + std::to_string(layer);
        record.text(prove_prefix + ".kind",
                    layer_kind_name(layer_kind(circuit.layers[layer])));
        emit_samples(record, prove_prefix + ".wall_ms",
                     prove_layer_wall[layer]);
        emit_samples(record, prove_prefix + ".cpu_ms",
                     prove_layer_cpu[layer]);
        record.text(verify_prefix + ".kind",
                    layer_kind_name(layer_kind(circuit.layers[layer])));
        const std::size_t measured_verifications =
            verify_layer_wall[layer].size();
        record.text(
            verify_prefix + ".status",
            measured_verifications == completed_iterations
                ? "measured"
                : measured_verifications == 0
                      ? "not-reached-before-rejection"
                      : "partial-before-rejection");
        emit_samples(record, verify_prefix + ".wall_ms",
                     verify_layer_wall[layer]);
        emit_samples(record, verify_prefix + ".cpu_ms",
                     verify_layer_cpu[layer]);
    }
    record.real("headline.prove_ms", prove_wall_summary.mean);
    record.real("headline.server_total_ms",
                payload_evaluation_timing.wall_ms + prove_wall_summary.mean +
                    serialize_wall_summary.mean);
    record.text(
        "headline.server_total_scope",
        Kind == ProtocolKind::Base
            ? "base-proof-and-serialization"
            : selected_packing_repetitions
                  ? "payload-fhe-evaluation-selected-gkr-packing-proof-and-"
                    "serialization"
                  : "payload-fhe-evaluation-diagnostic-nonselected-repetition-"
                    "gkr-packing-proof-and-serialization");
    record.real("headline.verify_including_decryption_ms",
                summarize(verify_wall).mean);
    record.real("headline.proof_decode_ms", decode_wall_summary.mean);
    record.real("headline.client_total_ms",
                (Kind != ProtocolKind::Base ? encryption_timing.wall_ms
                                             : 0.0) +
                    output_decryption_timing.wall_ms +
                    decode_wall_summary.mean +
                    summarize(verify_wall).mean);
    record.text(
        "headline.client_total_scope",
        Kind != ProtocolKind::Base
            ? "payload-input-encryption-output-decryption-proof-decoding-and-"
              "proof-verification"
            : "proof-verification");

    Adapter::emit_operation_counts(
        record,
        Kind != ProtocolKind::Base ? "payload_input_encryption"
                                   : "trace_encryption",
        encryption_counts);
    Adapter::emit_operation_counts(record, "payload_fhe_evaluation",
                                   payload_evaluation_counts);
    Adapter::emit_operation_counts(record, "payload_output_decryption",
                                   output_decryption_counts);
    Adapter::emit_operation_counts(
        record, "payload_output_error_diagnostic",
        output_error_diagnostic_counts);
    if constexpr (Kind != ProtocolKind::Base) {
        Adapter::emit_operation_counts(record, "gkr_proving",
                                       gkr_prove_counts);
    }
    Adapter::emit_operation_counts(record, "prove", prove_counts);
    Adapter::emit_operation_counts(record, "verify", verify_counts);
    if (schedule_formula) {
        // The selected Folded/Laned prover includes transcript packing after
        // GKR, while the schedule formula describes GKR layer reductions
        // only. Comparing the aggregate counter to that narrower formula
        // would incorrectly attribute packing rotations/additions to GKR.
        emit_schedule_formula(record, *schedule_formula, nullptr,
                              options.slots);
        record.text("formula.measured_comparison_scope",
                    "not-compared-selected-prove-includes-packing");
    } else {
        record.text("formula.version", "not-applicable-to-base");
    }
    record.integer("operations.prove.transcript_ciphertext_serializations",
                   proof_size.base_ciphertexts);
    record.integer("operations.proof_serialization.ciphertexts",
                   proof_size.base_ciphertexts);

    record.integer("proof.total_bytes", proof_size.total_bytes);
    record.integer("wire.canonical_proof_bytes", encoded_bytes);
    record.text(
        "wire.verification_boundary",
        Kind == ProtocolKind::Base
            ? "not-exercised-verifier-consumed-in-memory-proof"
            : "bounded-outer-decode-then-direct-semantic-verification;"
              "opaque-basefold-openings-parsed-once");
    record.integer("proof.statement_and_metadata_bytes",
                   proof_size.statement_and_metadata_bytes);
    record.integer("proof.round_message_bytes",
                   proof_size.round_message_bytes);
    record.integer("proof.terminal_message_bytes",
                   proof_size.terminal_message_bytes);
    record.integer("proof.partial_gate_mle_bytes",
                   proof_size.partial_gate_mle_bytes);
    record.integer("proof.gate_mle_opening_bytes",
                   proof_size.gate_mle_opening_bytes);
    emit_gate_mle_proof(record, Protocol::gkr_proof(*retained_proof));
    const std::size_t transcript_packing_transport_bytes =
        proof_size.transcript_packing_bytes;
    record.integer("proof.transcript_packing_bytes",
                   transcript_packing_transport_bytes);
    if constexpr (Kind != ProtocolKind::Base) {
        record.integer("proof.gkr_commitment_bytes",
                       proof_size.gkr_commitment_bytes);
        record.integer("proof.well_formedness_reveal_bytes",
                       proof_size.well_formedness_reveal_bytes);
        record.integer("proof.digit_packing_ciphertext_bytes",
                       proof_size.digit_packing_ciphertext_bytes);
        record.integer("proof.spartan_packing_proof_bytes",
                       proof_size.spartan_packing_proof_bytes);
        record.text("proof.transcript_packing_size_scope",
                    selected_packing_repetitions
                        ? "exact-selected-proof-components"
                        : "exact-diagnostic-proof-components");
    }
    record.integer("proof.logical_messages",
                   proof_size.logical_round_messages +
                       Protocol::gkr_proof(*retained_proof)
                           .reductions.size());
    record.integer("proof.extension_ciphertexts",
                   proof_size.extension_ciphertexts);
    record.integer("proof.base_ciphertexts", proof_size.base_ciphertexts);
    emit_samples(record, "proof.base_ciphertext_bytes",
                 proof_ciphertexts.bytes);
    emit_samples(record, "proof.rns_limbs", proof_ciphertexts.rns_limbs);
    emit_samples(record, "proof.coeff_modulus_bits",
                 proof_ciphertexts.modulus_bits);
    emit_samples(record, "noise.proof_public_estimate_bits",
                 proof_ciphertexts.estimated_noise_bits);
    emit_samples(record, "noise.trace_public_estimate_bits",
                 trace_ciphertexts.estimated_noise_bits);
    record.integer("noise.proof_minimum_public_estimate_bits",
                   proof_ciphertexts.minimum_noise);
    record.text("noise.proof_minimum_checkpoint",
                proof_ciphertexts.minimum_noise_checkpoint);
    record.integer("noise.trace_to_proof_minimum_public_loss_bits",
                   trace_ciphertexts.minimum_noise -
                       proof_ciphertexts.minimum_noise);
    if constexpr (Adapter::has_invariant_noise) {
        emit_samples(record, "noise.proof_measured_invariant_bits",
                     proof_measured_noise.budgets);
        emit_samples(record, "noise.trace_measured_invariant_bits",
                     trace_measured_noise.budgets);
        record.integer("noise.proof_minimum_measured_invariant_bits",
                       proof_measured_noise.minimum);
        record.text("noise.proof_minimum_measured_checkpoint",
                    proof_measured_noise.minimum_checkpoint);
        record.integer("noise.trace_to_proof_minimum_measured_loss_bits",
                       trace_measured_noise.minimum -
                           proof_measured_noise.minimum);
        record.text("noise.measurement_claim",
                    "client-secret-key-diagnostic-not-certificate");
    } else {
        record.text("noise.proof_measured_invariant_bits",
                    "not-available-for-mock");
        record.text("noise.measurement_claim", "public-mock-estimate-only");
    }
    if constexpr (Kind != ProtocolKind::Base) {
        record.integer("noise.payload_output_encrypted_values",
                       encrypted_output_count);
        record.integer("noise.payload_output_error_exclusive_threshold",
                       std::uint64_t{1}
                           << kPackedOutputCanonicalErrorBits);
        if (encrypted_output_count == 0) {
            record.text("noise.payload_output_rns_limbs_measured",
                        "not-applicable-no-encrypted-outputs");
            record.text("noise.payload_outputs_at_q0",
                        "not-applicable-no-encrypted-outputs");
            record.text("noise.payload_output_canonical_error_norm",
                        "not-applicable-no-encrypted-outputs");
            record.text("noise.payload_output_error_claim",
                        "public-output-values-have-no-ciphertext-error");
            record.text("noise.payload_output_error_gate",
                        "NOT-APPLICABLE-NO-ENCRYPTED-OUTPUTS");
        } else if (output_canonical_error_norm) {
            record.integer("noise.payload_output_rns_limbs_measured", 1);
            record.text(
                "noise.payload_outputs_at_q0",
                encrypted_outputs_at_q0.value_or(false)
                    ? "PASS"
                    : "not-available-for-backend");
            record.integer("noise.payload_output_canonical_error_norm",
                           *output_canonical_error_norm);
            record.integer("noise.payload_output_canonical_error_bits",
                           *output_canonical_error_bits);
            record.text("noise.payload_output_error_claim",
                        "secret-key-assisted-honest-run-diagnostic-not-certificate");
            record.text("noise.payload_output_error_gate", "PASS");
        } else {
            record.integer("noise.payload_output_rns_limbs_measured", 1);
            record.text(
                "noise.payload_outputs_at_q0",
                encrypted_outputs_at_q0.value_or(false)
                    ? "PASS"
                    : "not-available-for-backend");
            record.text("noise.payload_output_canonical_error_norm",
                        "not-available-for-backend");
            record.text("noise.payload_output_error_gate",
                        "NOT-AVAILABLE-FOR-BACKEND");
        }
    }
    record.text("verification.result", accepted ? "ACCEPT" : "REJECT");
    if (rejection_stage) {
        record.text("verification.rejection_stage", *rejection_stage);
    }
    progress.phase(accepted ? "complete" : "complete.rejected");
    progress.mark_complete(accepted);
    progress.emit(record);
    if (rejection_message) {
        std::cerr << "laminate_protocol_bench: " << *rejection_message
                  << '\n';
    }
    return accepted ? 0 : 1;
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> options = parse_options(argc, argv);
        if (!options) {
            return 0;
        }
        CompletedResultReport result_report(options->result_file);
        int status = 1;
        if (options->backend == BackendKind::Mock) {
            switch (options->protocol) {
            case ProtocolKind::Base:
                status = run<MockBackend, ProtocolKind::Base>(
                    *options, argc, argv, result_report.mirror());
                break;
            case ProtocolKind::Folded:
                status = run<MockBackend, ProtocolKind::Folded>(
                    *options, argc, argv, result_report.mirror());
                break;
            case ProtocolKind::Laned:
                status = run<MockBackend, ProtocolKind::Laned>(
                    *options, argc, argv, result_report.mirror());
                break;
            }
        } else {
#ifdef LAMINATE_WITH_SEAL
            switch (options->protocol) {
            case ProtocolKind::Base:
                status = run<SealBackend, ProtocolKind::Base>(
                    *options, argc, argv, result_report.mirror());
                break;
            case ProtocolKind::Folded:
                status = run<SealBackend, ProtocolKind::Folded>(
                    *options, argc, argv, result_report.mirror());
                break;
            case ProtocolKind::Laned:
                status = run<SealBackend, ProtocolKind::Laned>(
                    *options, argc, argv, result_report.mirror());
                break;
            }
#else
            throw std::invalid_argument(
                "seal-bgv backend requires a LAMINATE_WITH_SEAL build");
#endif
        }
        if (status == 0) {
            result_report.publish();
            if (!options->result_file.empty()) {
                std::cerr << "result published path="
                          << options->result_file.string()
                          << " verification=ACCEPT; render with "
                             "laminate_protocol_report_summary\n";
            } else {
                std::cerr << "result complete verification=ACCEPT; no "
                             "--result-file was requested\n";
            }
        }
        return status;
    } catch (const std::exception &error) {
        std::cerr << "laminate_protocol_bench: " << error.what() << '\n';
        return 1;
    }
}
