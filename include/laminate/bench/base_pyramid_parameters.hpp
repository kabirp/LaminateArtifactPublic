#ifndef LAMINATE_BENCH_BASE_PYRAMID_PARAMETERS_HPP
#define LAMINATE_BENCH_BASE_PYRAMID_PARAMETERS_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace laminate::bench {

// Exact parameters shared by the Base pyramid profile and its real-SEAL tests.
inline constexpr std::array<std::uint64_t, 11> kBasePyramidDataPrimes{
    1'053'858'393'162'252'289ULL, 15'032'614'913ULL, 53'687'910'401ULL,
    35'004'517'580'801ULL, 35'017'402'679'297ULL,
    35'047'467'909'121ULL, 35'092'565'753'857ULL,
    35'111'893'401'601ULL, 35'126'926'016'513ULL,
    35'144'106'147'841ULL, 35'156'991'246'337ULL};
inline constexpr std::uint64_t kBasePyramidSpecialPrime = 1'152'921'504'606'748'673ULL;
inline constexpr std::size_t kBasePyramidDataModulusBits = 490;
inline constexpr std::size_t kBasePyramidKeyModulusBits = 550;

} // namespace laminate::bench

#endif
