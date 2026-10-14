#ifndef LAMINATE_SPARTAN_IPCS_HPP
#define LAMINATE_SPARTAN_IPCS_HPP

/// @file ipcs.hpp
/// @brief Runtime interface for multilinear polynomial commitments.

#include "laminate/field/fq.hpp"
#include "laminate/field/fq2.hpp"
#include "laminate/transcript/public_coin.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace laminate::spartan {

/// Canonical 320-bit root carried by the selected PCS commitment.
using PcsDigest = std::array<std::uint8_t, 40>;

/// Scheme-independent commitment metadata bound by Spartan before any
/// challenge is sampled.
struct PcsCommitment {
    std::uint64_t scheme = 0;
    PcsDigest root{};
    std::uint64_t evaluation_count = 0;
    std::uint64_t width = 0;
    std::uint32_t log_rate = 0;
    std::uint32_t query_count = 0;

    bool operator==(const PcsCommitment &) const = default;
};

/// Canonical scheme-specific opening bytes.
struct PcsOpeningProof {
    std::vector<std::uint8_t> bytes;

    bool operator==(const PcsOpeningProof &) const = default;
};

/// Multilinear PCS over Fq with evaluation claims in Fq2.
class IPCS {
  public:
    class ProverState {
      public:
        virtual ~ProverState() = default;
    };

    struct CommitOutput {
        PcsCommitment commitment;
        std::shared_ptr<const ProverState> prover_state;
    };

    virtual ~IPCS() = default;

    virtual std::string_view name() const = 0;
    virtual std::uint64_t scheme_identifier() const = 0;

    /// Commit to power-of-two hypercube evaluations in MSB-first variable
    /// order. The opaque state remains only with the prover.
    virtual CommitOutput commit(std::span<const Fq> evaluations) const = 0;

    /// Commit equal-length columns in one interleaved Merkle tree.
    virtual CommitOutput commit_columns(
        const std::vector<std::vector<Fq>> &columns) const = 0;

    /// Open at an MSB-first extension-field point. The claimed value is an
    /// explicit input so the composing PIOP controls the terminal equation.
    virtual PcsOpeningProof open(
        const std::shared_ptr<const ProverState> &prover_state,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        PublicCoin &public_coin) const = 0;

    /// Open a verifier-specified extension-field linear combination of
    /// committed columns at one MSB-first point.
    virtual PcsOpeningProof open_linear_combination(
        const std::shared_ptr<const ProverState> &prover_state,
        std::span<const Fq2> column_weights,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        PublicCoin &public_coin) const = 0;

    virtual bool verify(const PcsCommitment &commitment,
                        std::span<const Fq2> point,
                        const Fq2 &claimed_value,
                        const PcsOpeningProof &proof,
                        PublicCoin &public_coin) const = 0;

    virtual bool verify_linear_combination(
        const PcsCommitment &commitment,
        std::span<const Fq2> column_weights,
        std::span<const Fq2> point, const Fq2 &claimed_value,
        const PcsOpeningProof &proof, PublicCoin &public_coin) const = 0;
};

/// Canonical bytes absorbed by Spartan for a PCS commitment.
std::vector<std::uint8_t>
encode_pcs_commitment(const PcsCommitment &commitment);

} // namespace laminate::spartan

#endif // LAMINATE_SPARTAN_IPCS_HPP
