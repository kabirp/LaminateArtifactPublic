#ifndef LAMINATE_BENCH_FOLDED_PYRAMID_PARAMETERS_HPP
#define LAMINATE_BENCH_FOLDED_PYRAMID_PARAMETERS_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace laminate::bench {

// Six-prime proof prefix followed by eight 45-bit payload heads.
inline constexpr std::array<std::uint64_t, 14> kFoldedPyramidDataPrimes{
    1'053'858'393'162'252'289ULL,
    281'412'698'669'057ULL, 281'449'206'448'129ULL,
    96'638'238'721ULL, 98'785'755'137ULL, 118'113'402'881ULL,
    35'004'517'580'801ULL, 35'017'402'679'297ULL,
    35'047'467'909'121ULL, 35'092'565'753'857ULL,
    35'111'893'401'601ULL, 35'126'926'016'513ULL,
    35'144'106'147'841ULL, 35'156'991'246'337ULL};
inline constexpr std::uint64_t kFoldedPyramidSpecialPrime =
    1'152'921'504'606'748'673ULL;
inline constexpr std::size_t kFoldedPyramidDataModulusBits = 626;
inline constexpr std::size_t kFoldedPyramidKeyModulusBits = 686;

} // namespace laminate::bench

#endif
