#ifndef LAMINATE_BENCH_NO_INTEGRITY_PARAMETERS_HPP
#define LAMINATE_BENCH_NO_INTEGRITY_PARAMETERS_HPP

/// @file no_integrity_parameters.hpp
/// @brief Exact payload-only benchmark chains and output-noise acceptance.

#include "laminate/bench/payload_profile.hpp"
#include "laminate/fhe/seal_backend.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace laminate::bench {

// Data primes are ordered from the output limb to the fresh input level.
// Each CT-CT multiplication layer consumes one prime.
inline fhe::SealParameters no_integrity_seal_parameters(
    const BenchmarkPayloadProfile &profile) {
    constexpr std::array<std::uint64_t, 7> quick_data_primes{
        18'014'336'227'311'617ULL,
        15'032'614'913ULL,
        53'687'910'401ULL,
        96'638'238'721ULL,
        98'785'755'137ULL,
        118'113'402'881ULL,
        122'408'435'713ULL,
    };
    constexpr std::array<std::uint64_t, 9> balanced_data_primes{
        1'152'921'497'895'862'273ULL,
        15'032'614'913ULL,
        122'408'435'713ULL,
        246'964'387'841ULL,
        272'734'584'833ULL,
        547'616'686'081ULL,
        140'720'308'191'233ULL,
        4'503'599'626'321'921ULL,
        9'007'072'549'175'297ULL,
    };
    constexpr std::array<std::uint64_t, 9> pyramid_data_primes{
        1'152'921'497'895'862'273ULL,
        36'028'481'325'662'209ULL,
        36'028'509'243'375'617ULL,
        36'028'635'946'844'161ULL,
        36'028'638'094'360'577ULL,
        36'028'674'602'139'649ULL,
        36'028'681'044'688'897ULL,
        36'028'700'372'336'641ULL,
        36'028'786'272'993'281ULL,
    };
    const bool pyramid = profile.tier == BenchmarkPayloadTier::TargetMulHeavy;
    const std::span<const std::uint64_t> data_primes = profile.is_target()
        ? std::span<const std::uint64_t>(
              pyramid ? pyramid_data_primes : balanced_data_primes)
        : std::span<const std::uint64_t>(quick_data_primes);
    const std::uint64_t special_prime = pyramid ? 36'028'797'017'456'641ULL
        : profile.is_target() ? 1'099'510'054'913ULL : 8'590'163'969ULL;
    if (profile.depth + 1U > data_primes.size()) {
        throw std::logic_error("noIntegrity payload depth exceeds its chain");
    }
    return fhe::SealParameters{
        .poly_modulus_degree = std::size_t{1} << 14U,
        .fresh_rns_limbs = profile.depth + 1U,
        .exact_data_primes = std::vector<std::uint64_t>(
            data_primes.begin(), data_primes.begin() +
                static_cast<std::ptrdiff_t>(profile.depth + 1U)),
        .exact_special_prime = special_prime,
        .special_prime_bits = static_cast<int>(std::bit_width(special_prime)),
        .security_level = pyramid ? seal::sec_level_type::none
                                 : seal::sec_level_type::tc128,
        .max_key_modulus_bits = pyramid ? 555U : profile.is_target() ? 438U : 0U,
        .generate_galois_keys = profile.rotate_gates != 0,
    };
}

inline std::string_view no_integrity_security_description(
    const BenchmarkPayloadProfile &profile) {
    return profile.tier == BenchmarkPayloadTier::TargetMulHeavy
        ? "SEAL sec_level_type::none (80-bit privacy target)"
        : "SEAL sec_level_type::tc128";
}

inline std::size_t no_integrity_data_modulus_bits(
    const fhe::SealParameters &parameters) {
    return fhe::NaturalMagnitude::product(parameters.exact_data_primes)
        .bit_count();
}

inline std::size_t no_integrity_key_modulus_bits(
    const fhe::SealParameters &parameters) {
    return fhe::NaturalMagnitude::multiply(
        fhe::NaturalMagnitude::product(parameters.exact_data_primes),
        parameters.exact_special_prime).bit_count();
}

inline void require_no_integrity_output_noise_budget(int budget) {
    if (budget <= 0) {
        throw std::runtime_error(
            "noIntegrity output has no positive invariant noise budget");
    }
}

} // namespace laminate::bench

#endif // LAMINATE_BENCH_NO_INTEGRITY_PARAMETERS_HPP
