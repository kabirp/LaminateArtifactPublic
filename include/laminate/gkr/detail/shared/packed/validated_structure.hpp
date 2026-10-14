#ifndef LAMINATE_GKR_DETAIL_SHARED_PACKED_VALIDATED_STRUCTURE_HPP
#define LAMINATE_GKR_DETAIL_SHARED_PACKED_VALIDATED_STRUCTURE_HPP

/// @file validated_structure.hpp
/// @brief Unforgeable evidence that one packed GKR proof was shape-checked.

#include "laminate/gates/outsourced.hpp"
#include "laminate/gkr/detail/shared/packed/proof.hpp"

#include <cstddef>
#include <span>
#include <variant>
#include <vector>

namespace laminate::gkr::detail {

/// Opaque evidence that a verifier already validated one exact proof shape.
///
/// `Validator` is the exact Folded or Laned verifier specialization allowed
/// to create and inspect this token. Making it part of the token type prevents
/// another caller from manufacturing a compatible specialization. The token
/// binds object identities and snapshots every proof field skipped by the
/// second structural-validation pass, so mutating a checked proof makes
/// `matches` fail closed.
template <typename PackedProof, typename Validator>
class ValidatedPackedGkrStructure final {
  public:
    ValidatedPackedGkrStructure(
        const ValidatedPackedGkrStructure &) = default;
    ValidatedPackedGkrStructure &operator=(
        const ValidatedPackedGkrStructure &) = default;

  private:
    struct ReductionShape {
        std::size_t alternative = 0;
        std::size_t round_count = 0;

        bool operator==(const ReductionShape &) const = default;
    };

    static std::vector<ReductionShape> capture_shapes(
        const PackedProof &proof) {
        std::vector<ReductionShape> shapes;
        shapes.reserve(proof.reductions.size());
        for (const auto &reduction : proof.reductions) {
            shapes.push_back(ReductionShape{
                reduction.index(),
                std::visit(
                    [](const auto &typed) {
                        return typed.rounds.size();
                    },
                    reduction)});
        }
        return shapes;
    }

    static bool shapes_match(
        const PackedProof &proof,
        std::span<const ReductionShape> expected) {
        if (proof.reductions.size() != expected.size()) {
            return false;
        }
        for (std::size_t index = 0; index < expected.size(); ++index) {
            const auto &reduction = proof.reductions[index];
            const ReductionShape actual{
                reduction.index(),
                std::visit(
                    [](const auto &typed) {
                        return typed.rounds.size();
                    },
                    reduction)};
            if (actual != expected[index]) {
                return false;
            }
        }
        return true;
    }

    ValidatedPackedGkrStructure(
        const PackedProof &proof,
        payload::TraceProvenance provenance, const Digest &trace_id,
        const PublicSetup &setup,
        const payload::LayeredCircuit &circuit)
        : proof_(&proof), provenance_(provenance), trace_id_(trace_id),
          setup_(&setup), circuit_(&circuit), header_(proof.header),
          reduction_shapes_(capture_shapes(proof)),
          has_gate_mle_opening_(proof.gate_mle_opening.has_value()) {}

    bool matches(
        const PackedProof &proof,
        payload::TraceProvenance provenance, const Digest &trace_id,
        const PublicSetup &setup,
        const payload::LayeredCircuit &circuit) const {
        return proof_ == &proof && provenance_ == provenance &&
               trace_id_ == trace_id && setup_ == &setup &&
               circuit_ == &circuit && header_ == proof.header &&
               shapes_match(proof, reduction_shapes_) &&
               has_gate_mle_opening_ ==
                   proof.gate_mle_opening.has_value();
    }

    const PackedProof *proof_;
    payload::TraceProvenance provenance_;
    Digest trace_id_;
    const PublicSetup *setup_;
    const payload::LayeredCircuit *circuit_;
    ProofHeader header_;
    std::vector<ReductionShape> reduction_shapes_;
    bool has_gate_mle_opening_ = false;

    friend Validator;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_PACKED_VALIDATED_STRUCTURE_HPP
