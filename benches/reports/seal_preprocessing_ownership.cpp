/// @file seal_preprocessing_ownership.cpp
/// @brief Exact ownership and timing report for SEAL Base preprocessing.

#include "benchmark_support.hpp"

#include "laminate/fhe/seal_backend.hpp"
#include "laminate/params.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <ostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

namespace laminate {
namespace {

using bench::Record;
using bench::Stopwatch;
using bench::SystemInfo;
using bench::Timing;
using fhe::SealBackend;
using fhe::SealParameters;

constexpr std::size_t kUnitRingDegree = std::size_t{1} << 10;
constexpr std::size_t kTargetRingDegree = std::size_t{1} << 14;
constexpr std::size_t kFreshModulusBitCap = 420;

struct Options {
    std::string run_tier = "unit";
    std::vector<std::uint64_t> data_primes;
    std::uint64_t special_prime = 0;
    bool data_primes_explicit = false;
    bool special_prime_explicit = false;

    Options() {
        const SealParameters current =
            fhe::make_depth8_diagnostic_parameters(true);
        if (current.exact_data_primes.size() < 3 ||
            current.exact_special_prime == 0) {
            throw std::logic_error(
                "current exact diagnostic chain is unavailable");
        }
        data_primes.assign(current.exact_data_primes.begin(),
                           current.exact_data_primes.begin() + 3);
        special_prime = current.exact_special_prime;
    }
};

[[noreturn]] void usage(const char *program, int status) {
    std::ostream &output = status == EXIT_SUCCESS ? std::cout : std::cerr;
    output
        << "Usage: " << program << " [options]\n"
        << "  --run-tier unit|target\n"
        << "  --data-primes q0,q1,...,qL  Exact bottom-to-top data chain\n"
        << "  --special-prime q            Exact key-switching prime\n"
        << "\n"
        << "The unit tier fixes N=1024 and defaults to a three-prime prefix "
           "of the current correction-preserving chain. The target tier "
           "fixes N=16384 and requires both exact-prime options explicitly.\n";
    std::exit(status);
}

std::uint64_t parse_u64(std::string_view text,
                        std::string_view option) {
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != text.data() + text.size()) {
        throw std::invalid_argument(
            std::string(option) + " expects an unsigned integer");
    }
    return result;
}

std::vector<std::uint64_t> parse_primes(
    std::string_view text, std::string_view option) {
    if (text.empty()) {
        throw std::invalid_argument(
            std::string(option) + " expects a nonempty comma-separated list");
    }
    std::vector<std::uint64_t> result;
    std::size_t begin = 0;
    while (begin <= text.size()) {
        const std::size_t comma = text.find(',', begin);
        const std::size_t end =
            comma == std::string_view::npos ? text.size() : comma;
        if (begin == end) {
            throw std::invalid_argument(
                std::string(option) + " contains an empty entry");
        }
        result.push_back(parse_u64(text.substr(begin, end - begin), option));
        if (comma == std::string_view::npos) {
            break;
        }
        begin = comma + 1;
    }
    return result;
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            usage(argv[0], EXIT_SUCCESS);
        }
        if (index + 1 == argc) {
            throw std::invalid_argument(
                std::string(argument) + " expects a value");
        }
        const std::string_view value(argv[++index]);
        if (argument == "--run-tier") {
            result.run_tier = value;
        } else if (argument == "--data-primes") {
            result.data_primes = parse_primes(value, argument);
            result.data_primes_explicit = true;
        } else if (argument == "--special-prime") {
            result.special_prime = parse_u64(value, argument);
            result.special_prime_explicit = true;
        } else {
            throw std::invalid_argument(
                "unknown option: " + std::string(argument));
        }
    }
    return result;
}

std::size_t ring_degree(const Options &options) {
    return options.run_tier == "target" ? kTargetRingDegree
                                         : kUnitRingDegree;
}

void validate_options(const Options &options) {
    if (options.run_tier != "unit" && options.run_tier != "target") {
        throw std::invalid_argument(
            "--run-tier must be unit or target");
    }
    if (options.data_primes_explicit !=
        options.special_prime_explicit) {
        throw std::invalid_argument(
            "exact data and special primes must be supplied together");
    }
    if (options.run_tier == "target" &&
        (!options.data_primes_explicit ||
         !options.special_prime_explicit)) {
        throw std::invalid_argument(
            "target runs require explicit --data-primes and --special-prime");
    }
    if (options.data_primes.size() < 2 ||
        options.data_primes.front() != kOuterFieldOrder ||
        options.special_prime == 0) {
        throw std::invalid_argument(
            "the exact chain must start at the outer field and have at least "
            "two data primes plus a special prime");
    }

    const std::uint64_t ntt_order =
        static_cast<std::uint64_t>(2 * ring_degree(options));
    std::vector<std::uint64_t> seen;
    seen.reserve(options.data_primes.size());
    for (const std::uint64_t prime : options.data_primes) {
        const std::size_t bits = std::bit_width(prime);
        if (bits < 20 || bits > 60 || prime % ntt_order != 1 ||
            prime % kBaseFieldOrder != 1 ||
            std::find(seen.begin(), seen.end(), prime) != seen.end()) {
            throw std::invalid_argument(
                "every data prime must be distinct, 20--60 bits, and one "
                "modulo both 2N and the plaintext modulus");
        }
        seen.push_back(prime);
    }
    const std::size_t special_bits =
        std::bit_width(options.special_prime);
    if (special_bits < 20 || special_bits > 60 ||
        options.special_prime % ntt_order != 1 ||
        std::find(seen.begin(), seen.end(), options.special_prime) !=
            seen.end()) {
        throw std::invalid_argument(
            "the special prime must be distinct, 20--60 bits, and one "
            "modulo 2N");
    }
}

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

std::vector<std::size_t> bit_widths(
    std::span<const std::uint64_t> values) {
    std::vector<std::size_t> result;
    result.reserve(values.size());
    for (const std::uint64_t value : values) {
        result.push_back(std::bit_width(value));
    }
    return result;
}

std::string parms_id_hex(const seal::parms_id_type &id) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < id.size(); ++index) {
        if (index != 0) {
            output << ':';
        }
        output << std::setw(16) << id[index];
    }
    return output.str();
}

std::uint64_t checked_u64(std::size_t value,
                          std::string_view quantity) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                std::string(quantity) + " exceeds uint64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          std::string_view quantity) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(quantity) + " overflows");
    }
    return left + right;
}

class CountingStreamBuffer final : public std::streambuf {
  public:
    std::uint64_t bytes() const { return bytes_; }

  protected:
    std::streamsize xsputn(const char *, std::streamsize count) override {
        if (count < 0 ||
            static_cast<std::uint64_t>(count) >
                std::numeric_limits<std::uint64_t>::max() - bytes_) {
            return 0;
        }
        bytes_ += static_cast<std::uint64_t>(count);
        return count;
    }

    int_type overflow(int_type character) override {
        if (traits_type::eq_int_type(character, traits_type::eof())) {
            return traits_type::not_eof(character);
        }
        if (bytes_ == std::numeric_limits<std::uint64_t>::max()) {
            return traits_type::eof();
        }
        ++bytes_;
        return character;
    }

    pos_type seekoff(off_type offset, std::ios_base::seekdir direction,
                     std::ios_base::openmode mode) override {
        if ((mode & std::ios_base::out) != std::ios_base::openmode{} &&
            direction == std::ios_base::cur && offset == 0 &&
            bytes_ <= static_cast<std::uint64_t>(
                          std::numeric_limits<std::streamoff>::max())) {
            return pos_type(static_cast<std::streamoff>(bytes_));
        }
        return pos_type(off_type(-1));
    }

  private:
    std::uint64_t bytes_ = 0;
};

/// Measure the exact uncompressed SEAL object encoding by invoking SEAL's own
/// serializer with a counting sink. This deliberately does not parse or
/// reproduce Laminate's context-bundle framing.
template <typename SealObject>
std::uint64_t exact_seal_object_bytes(const SealObject &object) {
    CountingStreamBuffer buffer;
    std::ostream output(&buffer);
    const std::streamoff written =
        object.save(output, seal::compr_mode_type::none);
    if (!output || written < 0 ||
        static_cast<std::uint64_t>(written) != buffer.bytes()) {
        throw std::runtime_error(
            "SEAL component serialization count failed");
    }
    return buffer.bytes();
}

std::uint64_t peak_rss_bytes() {
    return bench::system_info().peak_rss_bytes;
}

bool matches_current_target_chain(const Options &options) {
    const SealParameters current =
        fhe::make_depth8_diagnostic_parameters(true);
    return options.special_prime == current.exact_special_prime &&
           options.data_primes == current.exact_data_primes;
}

int run(const Options &options, int argc, char **argv) {
    validate_options(options);

    SealParameters parameters{
        .poly_modulus_degree = ring_degree(options),
        .fresh_rns_limbs = options.data_primes.size(),
        .exact_data_primes = options.data_primes,
        .exact_special_prime = options.special_prime,
        .special_prime_bits =
            static_cast<int>(std::bit_width(options.special_prime)),
        .security_level = seal::sec_level_type::none,
        .track_deterministic_noise_bounds = false,
        .max_fresh_ciphertext_modulus_bits = kFreshModulusBitCap,
        .generate_galois_keys = true,
    };

    const std::uint64_t baseline_peak_rss = peak_rss_bytes();

    Stopwatch generation_timer;
    SealBackend::Contexts contexts = SealBackend::create(parameters);
    const Timing generation_timing = generation_timer.stop();
    const std::uint64_t post_generation_peak_rss = peak_rss_bytes();

    require(SealBackend::storage_context_id(contexts.eval) ==
                SealBackend::storage_context_id(contexts.client),
            "client and evaluation context identities differ");
    std::vector<std::uint64_t> expected_key_moduli = options.data_primes;
    expected_key_moduli.push_back(options.special_prime);
    require(SealBackend::coefficient_moduli(contexts.eval) ==
                expected_key_moduli,
            "live SEAL context changed the exact modulus identities");

    Stopwatch evaluation_bundle_timer;
    std::vector<std::uint8_t> evaluation_bundle =
        SealBackend::serialize_evaluation_context_bundle(contexts.eval);
    const Timing evaluation_bundle_timing = evaluation_bundle_timer.stop();
    const std::uint64_t evaluation_bundle_bytes =
        checked_u64(evaluation_bundle.size(), "evaluation bundle");
    const std::uint64_t post_evaluation_bundle_peak_rss = peak_rss_bytes();
    std::vector<std::uint8_t>().swap(evaluation_bundle);

    Stopwatch client_bundle_timer;
    std::vector<std::uint8_t> client_bundle =
        SealBackend::serialize_client_context_bundle(contexts.client);
    const Timing client_bundle_timing = client_bundle_timer.stop();
    const std::uint64_t client_bundle_bytes =
        checked_u64(client_bundle.size(), "client bundle");
    const std::uint64_t post_client_bundle_peak_rss = peak_rss_bytes();
    std::vector<std::uint8_t>().swap(client_bundle);

    Stopwatch component_timer;
    const std::uint64_t public_key_bytes =
        exact_seal_object_bytes(*contexts.eval.public_key);
    const std::uint64_t relin_key_bytes =
        exact_seal_object_bytes(*contexts.eval.relin_keys);
    const std::uint64_t galois_key_bytes =
        exact_seal_object_bytes(*contexts.eval.galois_keys);
    const std::uint64_t secret_key_bytes =
        exact_seal_object_bytes(*contexts.client.secret_key);
    const Timing component_timing = component_timer.stop();
    const std::uint64_t post_component_peak_rss = peak_rss_bytes();

    require(public_key_bytes <= evaluation_bundle_bytes &&
                relin_key_bytes <= evaluation_bundle_bytes - public_key_bytes &&
                galois_key_bytes <=
                    evaluation_bundle_bytes - public_key_bytes -
                        relin_key_bytes,
            "evaluation bundle is smaller than its exact key encodings");
    require(public_key_bytes <= client_bundle_bytes &&
                secret_key_bytes <= client_bundle_bytes - public_key_bytes,
            "client bundle is smaller than its exact key encodings");
    const std::uint64_t evaluation_non_key_bytes =
        evaluation_bundle_bytes - public_key_bytes - relin_key_bytes -
        galois_key_bytes;
    const std::uint64_t client_non_key_bytes =
        client_bundle_bytes - public_key_bytes - secret_key_bytes;

    const auto first_data = contexts.eval.context->first_context_data();
    const auto key_data = contexts.eval.context->key_context_data();
    require(first_data && key_data, "SEAL context data is missing");

    const SystemInfo environment = bench::system_info();
    const Record record;
    record.text("format", "laminate-seal-preprocessing-ownership-v1");
    record.text(
        "classification.result_kind",
        "measured-single-thread-real-seal-preprocessing-ownership");
    record.text("classification.run_tier",
                options.run_tier == "target"
                    ? "target-explicit-exact-chain"
                    : "fast-unit-smoke-exact-chain-prefix");
    record.text("classification.threading",
                "single-threaded-driver-no-explicit-worker-threads");
    record.text(
        "classification.scope",
        "combined-context-key-generation-and-role-bundle-serialization-only");
    record.text(
        "classification.generation_timing",
        "seal-context-all-keys-role-wrappers-and-storage-identity-formation");
    record.text(
        "classification.serialized_bundle_bytes",
        "exact-canonical-uncompressed-v1-bytes-not-resident-memory");
    record.text(
        "classification.component_bytes",
        "exact-direct-seal-uncompressed-save-to-counting-stream-not-bundle-parser");
    record.text(
        "classification.peak_rss",
        "cumulative-whole-process-peak-from-process-start-not-resident-key-size");
    record.text(
        "classification.security",
        "seal-sec-level-none-measurement-not-privacy-or-integrity-estimate");
    record.text(
        "classification.ownership",
        "evaluation-bundle-server-client-bundle-client-private-public-key-duplicated");

    record.text("parameters.security_level", "none");
    record.integer("parameters.plaintext_modulus", kBaseFieldOrder);
    record.integer("parameters.poly_modulus_degree",
                   parameters.poly_modulus_degree);
    record.integer("parameters.fresh_rns_limbs",
                   parameters.fresh_rns_limbs);
    record.integer("parameters.fresh_modulus_bit_cap",
                   parameters.max_fresh_ciphertext_modulus_bits);
    record.text("parameters.exact_data_primes_bottom_to_top",
                bench::join(options.data_primes));
    record.text("parameters.data_prime_bit_widths_bottom_to_top",
                bench::join(bit_widths(options.data_primes)));
    record.integer("parameters.exact_special_prime",
                   options.special_prime);
    record.integer("parameters.special_prime_bit_width",
                   std::bit_width(options.special_prime));
    record.text("parameters.exact_key_moduli_bottom_to_top_then_special",
                bench::join(expected_key_moduli));
    record.integer(
        "parameters.fresh_modulus_product_exact_bits",
        SealBackend::fresh_ciphertext_modulus_bits(contexts.eval));
    record.integer(
        "parameters.fresh_modulus_prime_width_sum_bits",
        SealBackend::fresh_ciphertext_modulus_width_sum_bits(contexts.eval));
    record.integer("parameters.key_modulus_product_exact_bits",
                   SealBackend::key_modulus_bits(contexts.eval));
    record.integer("parameters.key_modulus_prime_width_sum_bits",
                   SealBackend::key_modulus_width_sum_bits(contexts.eval));
    record.text("parameters.generate_galois_keys", "yes");
    record.text("parameters.galois_key_scope",
                "seal-default-complete-rotation-key-set");
    record.text("parameters.all_data_primes_correction_preserving", "yes");
    record.text("parameters.matches_current_depth8_diagnostic_chain",
                matches_current_target_chain(options) ? "yes" : "no");

    record.text("identity.storage_context_id",
                bench::digest_hex(
                    SealBackend::storage_context_id(contexts.eval)));
    record.text("identity.fresh_seal_parms_id",
                parms_id_hex(first_data->parms_id()));
    record.text("identity.key_seal_parms_id",
                parms_id_hex(key_data->parms_id()));

    record.integer("ownership.server.evaluation_bundle_bytes",
                   evaluation_bundle_bytes);
    record.integer("ownership.server.public_key_blob_bytes",
                   public_key_bytes);
    record.integer("ownership.server.relinearization_key_blob_bytes",
                   relin_key_bytes);
    record.integer("ownership.server.galois_key_blob_bytes",
                   galois_key_bytes);
    record.integer(
        "ownership.server.bundle_non_key_descriptor_identity_framing_checksum_bytes",
        evaluation_non_key_bytes);
    record.integer("ownership.client.private_bundle_bytes",
                   client_bundle_bytes);
    record.integer("ownership.client.duplicated_public_key_blob_bytes",
                   public_key_bytes);
    record.integer("ownership.client.secret_key_blob_bytes",
                   secret_key_bytes);
    record.integer(
        "ownership.client.bundle_non_key_descriptor_identity_framing_checksum_bytes",
        client_non_key_bytes);
    record.integer("ownership.combined_role_bundle_bytes",
                   checked_add(evaluation_bundle_bytes, client_bundle_bytes,
                               "combined role bundle bytes"));
    record.text("ownership.prepared_plaintext_cache",
                "empty-no-entries-prepared");
    record.text("ownership.shared_manifest", "not-measured");

    bench::emit_timing(record, "context_key_generation_and_identity",
                       generation_timing);
    bench::emit_timing(record, "evaluation_bundle_serialization",
                       evaluation_bundle_timing);
    bench::emit_timing(record, "client_private_bundle_serialization",
                       client_bundle_timing);
    bench::emit_timing(record, "component_size_accounting",
                       component_timing);

    record.integer("memory.whole_process_peak_rss_before_generation_bytes",
                   baseline_peak_rss);
    record.integer(
        "memory.whole_process_peak_rss_after_generation_bytes",
        post_generation_peak_rss);
    record.integer(
        "memory.whole_process_peak_rss_after_evaluation_bundle_bytes",
        post_evaluation_bundle_peak_rss);
    record.integer(
        "memory.whole_process_peak_rss_after_client_bundle_bytes",
        post_client_bundle_peak_rss);
    record.integer(
        "memory.whole_process_peak_rss_after_component_accounting_bytes",
        post_component_peak_rss);
    record.integer("memory.whole_process_peak_rss_bytes",
                   environment.peak_rss_bytes);
    record.text(
        "memory.interpretation",
        "combined-client-server-process-plus-runtime-and-serialization-temporaries");
    record.text("memory.resident_key_size", "not-measured");

    record.text(
        "scope.excluded",
        "disk-allocation;current-rss;resident-key-size;"
        "prepared-plaintext-cache-entries-and-persistence;"
        "basefold-gatemle-r1cs-preprocessing;privacy-estimate;integrity-estimate");
    record.text("environment.command", bench::exact_command(argc, argv));
    record.text("environment.utc", bench::utc_timestamp());
    record.text("environment.git_commit", LAMINATE_GIT_COMMIT);
    record.text("environment.git_dirty", LAMINATE_GIT_DIRTY);
    record.text("environment.build_type", LAMINATE_BUILD_TYPE);
    record.text("environment.compiler", LAMINATE_COMPILER);
    record.text("environment.os", environment.os);
    record.text("environment.cpu", environment.cpu);
    record.integer("environment.ram_bytes", environment.ram_bytes);
    record.text("verification.result", "PASS");
    return 0;
}

} // namespace
} // namespace laminate

int main(int argc, char **argv) {
    try {
        const std::optional<laminate::Options> options =
            laminate::parse_options(argc, argv);
        if (!options) {
            return 0;
        }
        return laminate::run(*options, argc, argv);
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
