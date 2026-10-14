#ifndef LAMINATE_CRYPTO_POSEIDON_HPP
#define LAMINATE_CRYPTO_POSEIDON_HPP

/// @file poseidon.hpp
/// @brief R1CS-friendly Poseidon used only at circuit hash boundaries.

#include "laminate/field/fq.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace laminate {

/// Six canonical 60-bit field elements, encoded in six 64-bit words.
///
/// This type is deliberately distinct from the conventional SHA-256 Digest.
/// The selected proof-of-packing R1CS recomputes `HashCommitCT` values with
/// this representation.
using PoseidonDigest = std::array<std::uint8_t, 8 * kPoseidonDigestElements>;
using PoseidonState = std::array<Fq, kPoseidonWidth>;
using PoseidonRoundConstants =
    std::array<PoseidonState,
               kPoseidonFullRounds + kPoseidonPartialRounds>;
using PoseidonMdsMatrix =
    std::array<PoseidonState, kPoseidonWidth>;

enum class PoseidonDomain : std::uint64_t {
    CiphertextCommitment = 5,
};

/// Capacity-word encoding version and rate-padding delimiter shared by the
/// native sponge and its proof-of-packing R1CS gadget.  These are explicit
/// protocol constants so the structured circuit identity cannot drift from
/// host hashing through a duplicated literal.
inline constexpr std::uint64_t kPoseidonEncodingVersionDelimiter = 2;
inline constexpr std::uint64_t kPoseidonRatePaddingDelimiter = 1;

/// Hash canonical bytes. Seven-byte chunks are injectively embedded in Fq.
PoseidonDigest poseidon_hash(std::span<const std::uint8_t> input,
                             PoseidonDomain domain);

/// Native-field form used by the packing circuit. `logical_length` is
/// capacity-bound and may describe metadata not stored as a rate element.
PoseidonDigest poseidon_hash_fields(
    std::span<const Fq> input, PoseidonDomain domain,
    std::uint64_t logical_length);

/// Decode the six canonical field words carried by a Poseidon digest.
/// Throws when any 64-bit word is not a canonical native-field element.
std::array<Fq, kPoseidonDigestElements>
poseidon_digest_field_elements(const PoseidonDigest &digest);

/// Apply the fixed width-16 Poseidon permutation in place.
void poseidon_permute(std::array<Fq, kPoseidonWidth> &state);

/// Public deterministic parameters used by the matching R1CS gadget.
/// Exposing these values prevents host hashing and circuit synthesis from
/// maintaining separate constant tables.
const PoseidonRoundConstants &poseidon_round_constants();
const PoseidonMdsMatrix &poseidon_mds_matrix();
bool poseidon_round_is_full(std::size_t round);

/// R1CS synthesis materializes all 16 state words after full rounds and after
/// each group of five partial rounds.  These linear equality rows cap sparse
/// matrix density without changing the permutation.
bool poseidon_round_is_r1cs_checkpoint(std::size_t round);

/// Exact multiplication-constraint ledger for the x^5 S-box realization
/// x2=x*x, x4=x2*x2, x5=x4*x. Linear MDS work is absorbed into R1CS forms.
std::uint64_t poseidon_r1cs_constraints_for_field_elements(
    std::uint64_t field_elements);
std::uint64_t poseidon_r1cs_checkpoint_constraints_for_field_elements(
    std::uint64_t field_elements);
std::uint64_t poseidon_r1cs_constraints_for_bytes(
    std::uint64_t byte_count);

} // namespace laminate

#endif // LAMINATE_CRYPTO_POSEIDON_HPP
