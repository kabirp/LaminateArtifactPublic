#ifndef LAMINATE_PACKING_ANALYSIS_DETERMINISTIC_COMPLETENESS_HPP
#define LAMINATE_PACKING_ANALYSIS_DETERMINISTIC_COMPLETENESS_HPP

/// @file deterministic_completeness.hpp
/// @brief Typed hard-noise certificate across packing finalization.

#include "laminate/fhe/noise/deterministic.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace laminate::packing {

enum class DeterministicPackingCertificateScope : std::uint8_t {
    /// Bounds follow one ordinary backend execution.
    ExecutedChallengePath,
    /// Bounds come from a backend that retains every challenge-created zero
    /// term and therefore covers the complete prover challenge topology.
    ChallengeIndependentEnvelope,
};

struct DeterministicNoiseStageCertificate {
    struct Failure {
        std::size_t ciphertext_index = 0;
        fhe::DeterministicNoiseOperation operation =
            fhe::DeterministicNoiseOperation::FreshAsymmetricEncryption;
        fhe::DeterministicNoiseFailureReason reason =
            fhe::DeterministicNoiseFailureReason::CiphertextModulusWrap;
    };

    std::size_t ciphertext_count = 0;
    std::size_t tracked_ciphertexts = 0;
    std::size_t no_wrap_ciphertexts = 0;
    std::size_t minimum_rns_limbs = 0;
    std::size_t maximum_rns_limbs = 0;
    std::size_t maximum_partial_decryption_bits = 0;
    std::size_t maximum_canonical_error_bits = 0;
    std::size_t maximum_operation_count = 0;
    std::optional<Failure> first_failure;

    bool all_tracked() const {
        return ciphertext_count != 0 &&
               tracked_ciphertexts == ciphertext_count;
    }

    bool all_no_wrap() const {
        return all_tracked() && no_wrap_ciphertexts == ciphertext_count;
    }
};

/// Assess any flat ciphertext stage carrying public deterministic bounds.
/// This protocol-neutral entry point is also used by LaminateBase, whose
/// direct proof transport has no transcript-packing finalization stage.
template <CoefficientWellFormednessBackend Backend>
DeterministicNoiseStageCertificate assess_deterministic_noise_stage(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> ciphertexts,
    const fhe::DeterministicNoisePolicy &policy);

/// Certificate for BhIP-round ciphertexts, post-rotation aligned inputs, and
/// the canonical one-prime commitment boundary.
struct DeterministicPackingCompletenessCertificate {
    DeterministicPackingCertificateScope scope =
        DeterministicPackingCertificateScope::ExecutedChallengePath;
    DeterministicNoiseStageCertificate round;
    DeterministicNoiseStageCertificate aligned;
    DeterministicNoiseStageCertificate final;
    std::optional<fhe::NaturalMagnitude> maximum_final_error;
    std::uint64_t selected_final_error_cap = 0;
    bool final_error_fits_selected_cap = false;

    bool passes() const {
        return round.all_no_wrap() && aligned.all_no_wrap() &&
               final.all_no_wrap() && final_error_fits_selected_cap;
    }

    bool is_circuit_wide() const {
        return scope == DeterministicPackingCertificateScope::
                            ChallengeIndependentEnvelope;
    }
};

/// Assess one complete public bound derivation through alignment and bottom
/// normalization. The backend supplies bound metadata; no secret-key
/// diagnostic enters this function.
template <CoefficientWellFormednessBackend Backend>
DeterministicPackingCompletenessCertificate
certify_deterministic_packing_completeness(
    const typename Backend::EvalContext &eval,
    std::span<const typename Backend::Ciphertext> round_ciphertexts,
    const PackingLayout &layout,
    const fhe::DeterministicNoisePolicy &policy,
    std::uint64_t selected_final_error_cap,
    DeterministicPackingCertificateScope scope);

/// Mixed-value counterpart for Folded/Laned proof messages. Public values
/// participate in their canonical placements but contribute no FHE noise.
template <CoefficientWellFormednessBackend Backend>
DeterministicPackingCompletenessCertificate
certify_deterministic_packing_completeness(
    const typename Backend::EvalContext &eval,
    std::span<const fhe::FheValue<Backend>> round_values,
    const PackingLayout &layout,
    const fhe::DeterministicNoisePolicy &policy,
    std::uint64_t selected_final_error_cap,
    DeterministicPackingCertificateScope scope);

} // namespace laminate::packing

#include "laminate/packing/analysis/deterministic_completeness_impl.hpp"

#endif // LAMINATE_PACKING_ANALYSIS_DETERMINISTIC_COMPLETENESS_HPP
