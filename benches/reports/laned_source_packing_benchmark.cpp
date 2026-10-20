/// @file laned_source_packing_benchmark.cpp
/// @brief Single-thread comparison of Laned B-periodic packing kernels.

#include "benchmark_support.hpp"
#include "laned_source_packing_git_state.hpp"

#include "laminate/bench/packed_process_profile.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/fhe/value.hpp"
#include "laminate/payload/checkpoint/laned_witness_packing.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace laminate;
using namespace laminate::bench;
using namespace laminate::fhe;

namespace {

struct Options {
    std::size_t slots = 1024;
    std::size_t lanes = 1;
    std::size_t source_values = 1024;
    std::size_t natural_rns_limbs = 7;
    std::size_t ingress_rns_limbs = 5;
    std::size_t packed_rns_limbs = 4;
    std::size_t packed_outputs = 4;
    std::size_t iterations = 3;
};

std::optional<Options> parse_options(int argc, char **argv) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            std::cout
                << "Usage: laminate_laned_source_packing_bench [options]\n"
                << "  --slots N --lanes B --source-values W\n"
                << "  --natural-rns-limbs L --ingress-rns-limbs L\n"
                << "  --packed-rns-limbs L\n"
                << "  --packed-outputs P\n"
                << "  --iterations I\n";
            return std::nullopt;
        }
        if (index + 1 == argc) {
            throw std::invalid_argument("missing value after " +
                                        std::string(argument));
        }
        const std::string_view value(argv[++index]);
        if (argument == "--slots") {
            options.slots = parse_size(value, argument);
        } else if (argument == "--lanes") {
            options.lanes = parse_size(value, argument);
        } else if (argument == "--source-values") {
            options.source_values = parse_size(value, argument);
        } else if (argument == "--natural-rns-limbs") {
            options.natural_rns_limbs = parse_size(value, argument);
        } else if (argument == "--ingress-rns-limbs") {
            options.ingress_rns_limbs = parse_size(value, argument);
        } else if (argument == "--packed-rns-limbs") {
            options.packed_rns_limbs = parse_size(value, argument);
        } else if (argument == "--packed-outputs") {
            options.packed_outputs = parse_size(value, argument);
        } else if (argument == "--iterations") {
            options.iterations = parse_size(value, argument);
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }
    if (options.slots < 2 ||
        (options.slots & (options.slots - 1U)) != 0U ||
        options.lanes == 0 || options.slots % options.lanes != 0U ||
        options.source_values == 0 ||
        options.source_values > options.slots / options.lanes ||
        options.packed_rns_limbs == 0 ||
        options.packed_rns_limbs > options.ingress_rns_limbs ||
        options.ingress_rns_limbs > options.natural_rns_limbs ||
        options.natural_rns_limbs > 32 || options.packed_outputs == 0 ||
        options.packed_outputs >
            payload::kEagerLanedPackedCiphertextLimit ||
        options.iterations == 0) {
        throw std::invalid_argument("invalid Laned packing benchmark shape");
    }
    return options;
}

enum class Placement { RotateFirstChunk, DirectChunkMask };
enum class Normalization { BeforePacking, AfterPacking };

struct Sample {
    Timing timing;
    std::uint64_t checksum = 0;
    int noise_budget_bits = 0;
};

struct CachedMaskSample : Sample {
    std::uint64_t mask_preparations = 0;
    std::uint64_t mask_cache_hits = 0;
    std::uint64_t peak_mask_ntt_bytes = 0;
};

FheValue<SealBackend> pack_sources(
    const SealBackend::EvalContext &eval,
    const SealBackend::Ciphertext &natural_source,
    const Options &options, Placement placement,
    Normalization normalization) {
    SlotVector first_chunk(options.slots, Fp::zero());
    std::fill_n(first_chunk.begin(), options.lanes, Fp::one());
    std::optional<PreparedFpSlotBasis<SealBackend>> prepared_first;
    FheValue<SealBackend> accumulator =
        FheValue<SealBackend>::public_zero();

    for (std::size_t chunk = 0; chunk < options.source_values; ++chunk) {
        SealBackend::Ciphertext source = natural_source;
        if (normalization == Normalization::BeforePacking) {
            mod_switch_to_rns_limb_count<SealBackend>(
                eval, source, options.ingress_rns_limbs);
        }

        SealBackend::Ciphertext term;
        if (placement == Placement::RotateFirstChunk) {
            if (!prepared_first) {
                prepared_first = prepare_fp_slot_basis<SealBackend>(
                    eval, source, first_chunk);
            }
            term = mul_plain_prepared<SealBackend>(
                eval, source, *prepared_first);
            if (chunk != 0U) {
                term = SealBackend::rotate(
                    eval, term,
                    grid_inverse(options.slots,
                                 chunk * options.lanes));
            }
        } else {
            SlotVector chunk_mask(options.slots, Fp::zero());
            std::fill_n(
                chunk_mask.begin() +
                    static_cast<std::ptrdiff_t>(chunk * options.lanes),
                options.lanes, Fp::one());
            const auto prepared = prepare_fp_slot_basis<SealBackend>(
                eval, source, chunk_mask);
            term = mul_plain_prepared<SealBackend>(
                eval, source, prepared);
        }
        value_add_assign<SealBackend>(
            eval, accumulator,
            FheValue<SealBackend>::from_ciphertext(std::move(term)));
    }
    if (!accumulator.is_encrypted()) {
        throw std::logic_error("packing benchmark produced public output");
    }
    if (normalization == Normalization::AfterPacking ||
        options.packed_rns_limbs != options.ingress_rns_limbs) {
        mod_switch_to_rns_limb_count<SealBackend>(
            eval, accumulator.ciphertext(), options.packed_rns_limbs);
    }
    return accumulator;
}

Sample measure(const SealBackend::EvalContext &eval,
               const SealBackend::ClientContext &client,
               const SealBackend::Ciphertext &source,
               const Options &options, Placement placement,
               Normalization normalization) {
    FheValue<SealBackend> packed;
    const Timing timing = timed_void([&] {
        packed = pack_sources(eval, source, options, placement,
                              normalization);
    });
    const SlotVector slots = SealBackend::decrypt(
        client, packed.ciphertext());
    std::uint64_t checksum = 0;
    for (std::size_t index = 0; index < slots.size(); ++index) {
        checksum = checksum * 1'099'511'628'211ULL +
                   slots[index].value() + index;
    }
    return Sample{
        timing, checksum,
        SealBackend::invariant_noise_budget(client, packed.ciphertext())};
}

CachedMaskSample measure_cached_direct_masks(
    const SealBackend::EvalContext &eval,
    const SealBackend::ClientContext &client,
    const SealBackend::Ciphertext &natural_source,
    const Options &options) {
    payload::LanedWitnessMaskCache<SealBackend> cache(
        options.slots, options.lanes);
    std::vector<FheValue<SealBackend>> packed;
    std::uint64_t preparations = 0;
    std::uint64_t hits = 0;
    const Timing timing = timed_void([&] {
        packed.reserve(options.packed_outputs);
        for (std::size_t output = 0; output < options.packed_outputs;
             ++output) {
            FheValue<SealBackend> accumulator =
                FheValue<SealBackend>::public_zero();
            for (std::size_t chunk = 0;
                 chunk < options.source_values; ++chunk) {
                const auto prepared = cache.get(
                    eval, natural_source, chunk);
                preparations += prepared.prepared;
                hits += !prepared.prepared;
                value_add_assign<SealBackend>(
                    eval, accumulator,
                    FheValue<SealBackend>::from_ciphertext(
                        mul_plain_prepared<SealBackend>(
                            eval, natural_source, *prepared.basis)));
            }
            if (!accumulator.is_encrypted()) {
                throw std::logic_error(
                    "cached packing benchmark produced public output");
            }
            mod_switch_to_rns_limb_count<SealBackend>(
                eval, accumulator.ciphertext(),
                options.packed_rns_limbs);
            packed.push_back(std::move(accumulator));
        }
    });

    std::optional<std::uint64_t> expected_output_checksum;
    int minimum_noise = std::numeric_limits<int>::max();
    for (const FheValue<SealBackend> &value : packed) {
        const SlotVector slots = SealBackend::decrypt(
            client, value.ciphertext());
        std::uint64_t checksum = 0;
        for (std::size_t index = 0; index < slots.size(); ++index) {
            checksum = checksum * 1'099'511'628'211ULL +
                       slots[index].value() + index;
        }
        if (expected_output_checksum &&
            *expected_output_checksum != checksum) {
            throw std::runtime_error(
                "cached packing outputs decrypted differently");
        }
        expected_output_checksum = checksum;
        minimum_noise = std::min(
            minimum_noise,
            SealBackend::invariant_noise_budget(
                client, value.ciphertext()));
    }
    return CachedMaskSample{
        Sample{timing, *expected_output_checksum, minimum_noise},
        preparations, hits, cache.peak_ntt_bytes()};
}

const char *placement_name(Placement placement) {
    return placement == Placement::RotateFirstChunk
               ? "rotate_first_chunk"
               : "direct_chunk_mask";
}

const char *normalization_name(Normalization normalization) {
    return normalization == Normalization::BeforePacking
               ? "normalize_each_then_pack"
               : "pack_then_normalize_once";
}

} // namespace

int main(int argc, char **argv) try {
    const auto parsed = parse_options(argc, argv);
    if (!parsed) {
        return 0;
    }
    const Options options = *parsed;
    const std::vector<int> data_prime_bit_sizes =
        packed_benchmark_data_prime_bit_sizes(
            options.natural_rns_limbs);
    const std::size_t fresh_modulus_bits =
        std::accumulate(data_prime_bit_sizes.begin(),
                        data_prime_bit_sizes.end(), std::size_t{0});
    SealParameters parameters{
        .poly_modulus_degree = options.slots,
        .fresh_rns_limbs = options.natural_rns_limbs,
        .data_prime_bit_sizes = data_prime_bit_sizes,
        .special_prime_bits = 60,
        .security_level = seal::sec_level_type::none,
        .max_fresh_ciphertext_modulus_bits = fresh_modulus_bits,
        .max_key_modulus_bits = fresh_modulus_bits + 60U,
        .generate_galois_keys = true,
    };
    auto contexts = SealBackend::create(parameters);

    SlotVector plaintext(options.slots, Fp::zero());
    for (std::size_t lane = 0; lane < options.lanes; ++lane) {
        plaintext[lane] = Fp(17U + lane);
    }
    for (std::size_t chunk = 1;
         chunk < options.slots / options.lanes; ++chunk) {
        std::copy_n(plaintext.begin(), options.lanes,
                    plaintext.begin() + static_cast<std::ptrdiff_t>(
                                            chunk * options.lanes));
    }
    SealBackend::Ciphertext source = SealBackend::encrypt(
        contexts.client, plaintext);
    mod_switch_to_rns_limb_count<SealBackend>(
        contexts.eval, source, options.natural_rns_limbs);

    Record record;
    record.text("format", "laminate-laned-source-packing-kernels-v2");
    record.text("classification", "measured-single-thread-real-seal-bgv");
    record.text("execution.threading",
                "single-threaded-driver-no-explicit-worker-threads");
    record.text("environment.git_commit", LAMINATE_GIT_COMMIT);
    record.text("environment.git_dirty", LAMINATE_GIT_DIRTY);
    record.text("environment.build_type", LAMINATE_BUILD_TYPE);
    record.text("environment.compiler", LAMINATE_COMPILER);
    record.text("environment.seal_version", LAMINATE_SEAL_VERSION);
    record.text("environment.seal_acceleration", LAMINATE_SEAL_ACCELERATION);
    record.text("command", exact_command(argc, argv));
    record.integer("geometry.slots", options.slots);
    record.integer("geometry.lanes", options.lanes);
    record.integer("geometry.source_values", options.source_values);
    record.integer("parameters.natural_rns_limbs",
                   options.natural_rns_limbs);
    record.integer("parameters.ingress_rns_limbs",
                   options.ingress_rns_limbs);
    record.integer("parameters.packed_rns_limbs",
                   options.packed_rns_limbs);
    record.integer("geometry.packed_outputs", options.packed_outputs);
    const std::vector<std::uint64_t> data_primes =
        SealBackend::data_coefficient_moduli(contexts.eval, source);
    record.integer("parameters.bottom_data_prime", data_primes.front());
    record.text("parameters.bottom_data_prime_is_native_fq",
                data_primes.front() == kOuterFieldOrder ? "yes" : "no");
    record.integer("measurement.iterations", options.iterations);

    std::optional<std::uint64_t> expected_checksum;
    std::optional<double> uncached_direct_after_wall_ms;
    for (const Placement placement :
         {Placement::RotateFirstChunk, Placement::DirectChunkMask}) {
        for (const Normalization normalization :
             {Normalization::BeforePacking,
              Normalization::AfterPacking}) {
            std::vector<double> wall;
            std::vector<double> cpu;
            int minimum_noise = std::numeric_limits<int>::max();
            for (std::size_t iteration = 0;
                 iteration < options.iterations; ++iteration) {
                const Sample sample = measure(
                    contexts.eval, contexts.client, source, options,
                    placement, normalization);
                if (expected_checksum &&
                    *expected_checksum != sample.checksum) {
                    throw std::runtime_error(
                        "packing kernels decrypted to different values");
                }
                expected_checksum = sample.checksum;
                wall.push_back(sample.timing.wall_ms);
                cpu.push_back(sample.timing.cpu_ms);
                minimum_noise = std::min(minimum_noise,
                                         sample.noise_budget_bits);
            }
            std::sort(wall.begin(), wall.end());
            std::sort(cpu.begin(), cpu.end());
            const std::string prefix =
                std::string("kernel.") + placement_name(placement) + "." +
                normalization_name(normalization);
            record.real(prefix + ".median_wall_ms",
                        wall[wall.size() / 2U]);
            record.real(prefix + ".median_cpu_ms",
                        cpu[cpu.size() / 2U]);
            record.real(prefix + ".source_values_per_second",
                        1000.0 * static_cast<double>(options.source_values) /
                            wall[wall.size() / 2U]);
            record.integer(prefix + ".minimum_noise_budget_bits",
                           minimum_noise);
            if (placement == Placement::DirectChunkMask &&
                normalization == Normalization::AfterPacking) {
                uncached_direct_after_wall_ms = wall[wall.size() / 2U];
            }
        }
    }
    std::vector<double> cached_wall;
    std::vector<double> cached_cpu;
    std::uint64_t cached_preparations = 0;
    std::uint64_t cached_hits = 0;
    std::uint64_t cached_peak_ntt_bytes = 0;
    int cached_minimum_noise = std::numeric_limits<int>::max();
    for (std::size_t iteration = 0; iteration < options.iterations;
         ++iteration) {
        const CachedMaskSample sample = measure_cached_direct_masks(
            contexts.eval, contexts.client, source, options);
        if (*expected_checksum != sample.checksum) {
            throw std::runtime_error(
                "cached packing disagrees with uncached kernels");
        }
        cached_wall.push_back(sample.timing.wall_ms);
        cached_cpu.push_back(sample.timing.cpu_ms);
        cached_preparations = sample.mask_preparations;
        cached_hits = sample.mask_cache_hits;
        cached_peak_ntt_bytes = std::max(
            cached_peak_ntt_bytes, sample.peak_mask_ntt_bytes);
        cached_minimum_noise = std::min(
            cached_minimum_noise, sample.noise_budget_bits);
    }
    std::sort(cached_wall.begin(), cached_wall.end());
    std::sort(cached_cpu.begin(), cached_cpu.end());
    const double cached_median = cached_wall[cached_wall.size() / 2U];
    const double uncached_projection =
        *uncached_direct_after_wall_ms *
        static_cast<double>(options.packed_outputs);
    const std::string cached_prefix =
        "kernel.direct_chunk_mask.pack_then_normalize_once.cached_masks";
    record.real(cached_prefix + ".median_wall_ms", cached_median);
    record.real(cached_prefix + ".median_cpu_ms",
                cached_cpu[cached_cpu.size() / 2U]);
    record.real(cached_prefix + ".source_applications_per_second",
                1000.0 * static_cast<double>(options.source_values) *
                    static_cast<double>(options.packed_outputs) /
                    cached_median);
    record.integer(cached_prefix + ".mask_preparations",
                   cached_preparations);
    record.integer(cached_prefix + ".mask_cache_hits", cached_hits);
    record.integer(cached_prefix + ".peak_mask_ntt_bytes",
                   cached_peak_ntt_bytes);
    record.integer(cached_prefix + ".minimum_noise_budget_bits",
                   cached_minimum_noise);
    record.real(cached_prefix + ".uncached_projected_wall_ms",
                uncached_projection);
    record.real(cached_prefix + ".speedup_vs_uncached_projection",
                uncached_projection / cached_median);
    record.integer("correctness.decrypted_checksum",
                   *expected_checksum);
    record.text("correctness.all_kernels_equal", "yes");
    return 0;
} catch (const std::exception &error) {
    std::cerr << "error: " << error.what() << '\n';
    return 1;
}
