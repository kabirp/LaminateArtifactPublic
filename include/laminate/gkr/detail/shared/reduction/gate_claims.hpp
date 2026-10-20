#ifndef LAMINATE_GKR_DETAIL_SHARED_REDUCTION_GATE_CLAIMS_HPP
#define LAMINATE_GKR_DETAIL_SHARED_REDUCTION_GATE_CLAIMS_HPP

/// @file gate_claims.hpp
/// @brief Profile-aware online gate-claim channels for GKR orchestration.

#include "laminate/gates/outsourced.hpp"
#include "laminate/setup.hpp"

#include <memory>
#include <optional>
#include <stdexcept>

namespace laminate::gkr::detail {

/// Prover-side claim channel. Direct/dummy profiles do no extra work; the
/// outsourced profile records only protocol-visible terminal evaluations.
class ProverGateClaims {
  public:
    ProverGateClaims(const payload::LayeredCircuit &circuit,
                     const PublicSetup &setup, Transcript &transcript)
        : profile_(setup.gate_mle_profile), direct_(circuit) {
        if (profile_ == GateMleProfile::OutsourcedBaseFold) {
            if (!setup.outsourced_gate_mle) {
                throw std::invalid_argument(
                    "ProverGateClaims: missing verifier key");
            }
            outsourced_.emplace(circuit,
                                setup.outsourced_gate_mle->layout,
                                transcript);
        }
    }

    bool requires_opening() const { return outsourced_.has_value(); }

    Fpk evaluate(const gates::GateMleQuery &query) {
        return outsourced_ ? outsourced_->evaluate(query)
                           : direct_.evaluate(query);
    }

    Fpk evaluate_affine_constant(
        std::size_t layer, std::span<const Fpk> point) {
        return outsourced_
                   ? outsourced_->evaluate_affine_constant(layer, point)
                   : direct_.evaluate_affine_constant(layer, point);
    }

    std::optional<gates::OutsourcedGateMleProof> finish(
        const std::shared_ptr<const gates::GateTableProverKey> &key) {
        if (!outsourced_) {
            if (key) {
                throw std::invalid_argument(
                    "ProverGateClaims: direct profile carries prover key");
            }
            return std::nullopt;
        }
        if (!key) {
            throw std::invalid_argument(
                "ProverGateClaims: outsourced profile lacks prover key");
        }
        return outsourced_->finish(*key);
    }

  private:
    GateMleProfile profile_;
    gates::DirectGateMle direct_;
    std::optional<gates::GateClaimProver> outsourced_;
};

/// Verifier-side channel. Outsourced online values remain provisional until
/// `finish()` authenticates their complete ordered batch.
class VerifierGateClaims {
  public:
    VerifierGateClaims(
        const payload::LayeredCircuit &circuit, const PublicSetup &setup,
        const std::optional<gates::OutsourcedGateMleProof> &proof,
        Transcript &transcript)
        : direct_(circuit) {
        const bool expected = setup.gate_mle_profile ==
                              GateMleProfile::OutsourcedBaseFold;
        if (proof.has_value() != expected) {
            throw std::invalid_argument(
                "VerifierGateClaims: proof/profile mismatch");
        }
        if (expected) {
            if (!setup.outsourced_gate_mle) {
                throw std::invalid_argument(
                    "VerifierGateClaims: missing verifier key");
            }
            outsourced_.emplace(*setup.outsourced_gate_mle, *proof,
                                transcript);
        }
    }

    Fpk evaluate(const gates::GateMleQuery &query) {
        return outsourced_ ? outsourced_->evaluate(query)
                           : direct_.evaluate(query);
    }

    Fpk evaluate_affine_constant(
        std::size_t layer, std::span<const Fpk> point) {
        return outsourced_
                   ? outsourced_->evaluate_affine_constant(layer, point)
                   : direct_.evaluate_affine_constant(layer, point);
    }

    Fpk evaluate_affine_pair(
        std::size_t layer, std::span<const Fpk> first_output,
        std::span<const Fpk> second_output,
        std::span<const Fpk> source, const Fpk &second_weight) {
        if (!outsourced_) {
            return direct_.evaluate_affine_pair(
                layer, first_output, second_output, source,
                second_weight);
        }
        const Fpk first = outsourced_->evaluate(
            gates::GateMleQuery{gates::AffineQuery{
                layer, first_output, source}});
        const Fpk second = outsourced_->evaluate(
            gates::GateMleQuery{gates::AffineQuery{
                layer, second_output, source}});
        return first + second_weight * second;
    }

    Fpk evaluate_affine_constant_pair(
        std::size_t layer, std::span<const Fpk> first_output,
        std::span<const Fpk> second_output,
        const Fpk &second_weight) {
        if (!outsourced_) {
            return direct_.evaluate_affine_constant_pair(
                layer, first_output, second_output, second_weight);
        }
        const Fpk first = outsourced_->evaluate_affine_constant(
            layer, first_output);
        const Fpk second = outsourced_->evaluate_affine_constant(
            layer, second_output);
        return first + second_weight * second;
    }

    bool finish() { return !outsourced_ || outsourced_->finish(); }

  private:
    gates::DirectGateMle direct_;
    std::optional<gates::GateClaimVerifier> outsourced_;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_REDUCTION_GATE_CLAIMS_HPP
