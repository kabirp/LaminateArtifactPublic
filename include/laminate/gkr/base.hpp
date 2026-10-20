#ifndef LAMINATE_GKR_BASE_HPP
#define LAMINATE_GKR_BASE_HPP

/// @file base.hpp
/// @brief Encrypted GKR messages for the LaminateBase reduction schedule.

#include "laminate/fhe/extension.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/gkr/proof.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace laminate::gkr {

inline constexpr std::uint64_t kEncryptedBaseProofVersion = 8;

/// Boolean evaluations of a gate MLE after every non-slot coordinate has
/// been fixed. The verifier binds this vector before sampling its slot point.
struct PartialGateMleVector {
    std::vector<Fpk> evaluations;

    bool operator==(const PartialGateMleVector &) const = default;
};

template <fhe::FheBackend Backend>
struct EncryptedBaseLayerReductionSumcheckRound {
    /// Public-or-encrypted per-slot Boolean endpoint and X=2 evaluation.
    /// Affine sends R(1); equality-stripped multiplication sends S(0), except
    /// at tau=0 where it sends S(1) to avoid division by zero.
    std::array<fhe::ExtensionValue<Backend>, 2> evaluations;
};

template <fhe::FheBackend Backend> struct EncryptedBaseAffineLayerReduction {
    std::vector<EncryptedBaseLayerReductionSumcheckRound<Backend>> rounds;
    /// Slots hold W(r_wire, l) for every Boolean SIMD slot l.
    fhe::ExtensionValue<Backend> source_vector;
    /// h(l) = G(output_claim; r_wire, l).
    PartialGateMleVector partial_gate_mle;
};

template <fhe::FheBackend Backend>
struct EncryptedBaseMultiplicationLayerReduction {
    std::vector<EncryptedBaseLayerReductionSumcheckRound<Backend>> rounds;
    /// Slots hold the dense left/right source MLEs at the common
    /// ciphertext-index point.
    std::array<fhe::ExtensionValue<Backend>, 2> source_vectors;
};

template <fhe::FheBackend Backend>
using EncryptedBaseLayerReductionProof =
    std::variant<EncryptedBaseAffineLayerReduction<Backend>,
                 EncryptedBaseMultiplicationLayerReduction<Backend>>;

template <fhe::FheBackend Backend> struct EncryptedBaseProof {
    ProofHeader header;
    std::vector<EncryptedBaseLayerReductionProof<Backend>> reductions;
    std::optional<gates::OutsourcedGateMleProof> gate_mle_opening;
};

} // namespace laminate::gkr

#endif // LAMINATE_GKR_BASE_HPP
