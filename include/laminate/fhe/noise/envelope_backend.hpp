#ifndef LAMINATE_FHE_NOISE_ENVELOPE_BACKEND_HPP
#define LAMINATE_FHE_NOISE_ENVELOPE_BACKEND_HPP

/// @file envelope_backend.hpp
/// @brief Bound-only backend for challenge-independent prover certificates.
///
/// This backend does not model ciphertext values. It executes the same typed
/// prover orchestration while carrying only the public deterministic BGV
/// coefficient bound and RNS level. In particular, it accepts algebraically
/// zero plaintexts and charges them as a worst-case nonzero operation. This
/// lets an offline certificate retain every structurally possible term even
/// when one concrete Fiat--Shamir assignment would make that term vanish.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/noise/deterministic.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace laminate::fhe {

struct NoiseEnvelopeParameters {
    DeterministicNoisePolicy policy;
    /// Data primes in SEAL chain order `[q_0,...,q_L]`; switching drops the
    /// final entry. The special key-switching prime is stored separately.
    std::vector<std::uint64_t> data_moduli;
    std::uint64_t special_modulus = 0;

    void validate() const;
};

/// Public-bound execution backend.
///
/// `Ciphertext::deterministic_noise_bound` is the only cryptographic payload.
/// Identity detects structurally identical operands so raw cancellation can
/// be rejected and represented by the mixed-value layer as public zero.
class NoiseEnvelopeBackend {
  public:
    struct IdentityState;

    struct Ciphertext {
        DeterministicNoiseBound deterministic_noise_bound;
        std::size_t rns_limbs = 0;
        std::size_t component_count = 2;
        std::uint64_t identity = 0;
        /// Numeric identities are meaningful only within this owner token.
        std::shared_ptr<IdentityState> context_token;

        std::size_t size() const { return component_count; }
    };

    using ExtCiphertext = ExtensionCiphertext<Ciphertext>;

    struct PreparedSlotBasis {
        SlotVector plaintext;
    };

    struct PreparedLevelSlotBasis {
        SlotVector plaintext;
        std::size_t rns_limbs = 0;
    };

    struct PreparedExtensionSlotBasis {
        PlainExtension plaintext;
        std::size_t rns_limbs = 0;
    };

    struct IdentityState {
        std::uint64_t next = 1;
    };

    struct EvalContext {
        NoiseEnvelopeParameters parameters;
        std::shared_ptr<IdentityState> identities;
    };

    struct ClientContext {
        NoiseEnvelopeParameters parameters;
        std::shared_ptr<IdentityState> identities;
    };

    struct Contexts {
        EvalContext eval;
        ClientContext client;
    };

    static Contexts create(NoiseEnvelopeParameters parameters);

    static Ciphertext encrypt(const ClientContext &context,
                              const SlotVector &slots);
    static SlotVector decrypt(const ClientContext &context,
                              const Ciphertext &ciphertext);

    static Ciphertext negate(const EvalContext &context,
                             const Ciphertext &ciphertext);
    static Ciphertext add(const EvalContext &context, const Ciphertext &left,
                          const Ciphertext &right);
    static bool same_ciphertext(const EvalContext &context,
                                const Ciphertext &left,
                                const Ciphertext &right);
    static Ciphertext sub(const EvalContext &context, const Ciphertext &left,
                          const Ciphertext &right);
    static Ciphertext mul_no_relin(const EvalContext &context,
                                   const Ciphertext &left,
                                   const Ciphertext &right);
    static void relinearize(const EvalContext &context,
                            Ciphertext &ciphertext);
    static Ciphertext mul(const EvalContext &context, const Ciphertext &left,
                          const Ciphertext &right);
    static Ciphertext add_plain(const EvalContext &context,
                                const Ciphertext &ciphertext,
                                const SlotVector &plaintext);
    /// Scalar-plaintext addition with an O(1)-sized host representation.
    static Ciphertext add_plain_scalar(const EvalContext &context,
                                       const Ciphertext &ciphertext,
                                       const Fp &plaintext);
    static Ciphertext mul_plain(const EvalContext &context,
                                const Ciphertext &ciphertext,
                                const SlotVector &plaintext);
    /// Scalar-plaintext topology with an O(1)-sized host representation.
    static Ciphertext mul_plain_scalar(const EvalContext &context,
                                       const Ciphertext &ciphertext,
                                       const Fp &plaintext);
    static PreparedSlotBasis prepare_slot_basis(
        const EvalContext &context, const SlotVector &basis);
    static Ciphertext mul_plain_prepared(
        const EvalContext &context, const Ciphertext &ciphertext,
        const PreparedSlotBasis &basis);
    static PreparedLevelSlotBasis prepare_level_slot_basis(
        const EvalContext &context, const Ciphertext &level_reference,
        const SlotVector &basis);
    static Ciphertext mul_plain_level_prepared(
        const EvalContext &context, const Ciphertext &ciphertext,
        const PreparedLevelSlotBasis &basis);
    static PreparedBasisStorageStats prepared_level_slot_basis_storage(
        const PreparedLevelSlotBasis &basis);
    static void preprocess_fixed_message_cells(const EvalContext &context);
    static Ciphertext mul_plain_fixed_message_cell(
        const EvalContext &context, const Ciphertext &ciphertext,
        std::size_t cell);
    static PreparedExtensionSlotBasis prepare_extension_slot_basis(
        const EvalContext &context, const Ciphertext &level_reference,
        const PlainExtension &basis);
    static ExtCiphertext ext_mul_plain_prepared(
        const EvalContext &context, const ExtCiphertext &ciphertext,
        const PreparedExtensionSlotBasis &basis);
    static ExtCiphertext promote_plain_prepared(
        const EvalContext &context, const Ciphertext &ciphertext,
        const PreparedExtensionSlotBasis &basis);
    static PreparedBasisStorageStats prepared_extension_slot_basis_storage(
        const PreparedExtensionSlotBasis &basis);
    static Ciphertext rotate(const EvalContext &context,
                             const Ciphertext &ciphertext,
                             std::size_t steps);
    static Ciphertext fold(const EvalContext &context,
                           const Ciphertext &ciphertext);

    static ExtCiphertext ext_add(const EvalContext &context,
                                 const ExtCiphertext &left,
                                 const ExtCiphertext &right);
    static ExtCiphertext ext_sub(const EvalContext &context,
                                 const ExtCiphertext &left,
                                 const ExtCiphertext &right);
    static ExtCiphertext ext_mul_no_relin(const EvalContext &context,
                                          const ExtCiphertext &left,
                                          const ExtCiphertext &right);
    static void ext_relinearize(const EvalContext &context,
                                ExtCiphertext &ciphertext);
    static ExtCiphertext ext_mul(const EvalContext &context,
                                 const ExtCiphertext &left,
                                 const ExtCiphertext &right);
    static ExtCiphertext ext_mul_plain(const EvalContext &context,
                                       const ExtCiphertext &ciphertext,
                                       const PlainExtension &plaintext);
    /// Dense challenge-independent extension-scalar topology.
    static ExtCiphertext ext_mul_plain_scalar(
        const EvalContext &context, const ExtCiphertext &ciphertext,
        const PlainExtensionScalar &plaintext);
    static void mod_switch_to_next(const EvalContext &context,
                                   Ciphertext &ciphertext);
    static void mod_switch_to_lowest(const EvalContext &context,
                                     Ciphertext &ciphertext);
    static std::size_t remaining_mult_depth(const EvalContext &context,
                                            const Ciphertext &ciphertext);
    static std::size_t rns_limb_count(const EvalContext &context,
                                      const Ciphertext &ciphertext);
    static std::size_t coeff_modulus_bits(const EvalContext &context,
                                          const Ciphertext &ciphertext);
    static int estimated_noise_bits(const EvalContext &context,
                                    const Ciphertext &ciphertext);

    static std::size_t slot_count(const EvalContext &context);
    static std::size_t slot_count(const ClientContext &context);
    static std::vector<std::uint8_t>
    serialize(const Ciphertext &ciphertext);

    /// Generic prover helpers use this marker to retain challenge-created
    /// zero terms and unit scales. Ordinary backends omit the marker and keep
    /// their performance shortcuts.
    static bool forces_challenge_independent_topology(
        const EvalContext &) {
        return true;
    }

    // Coefficient-boundary operations let the ordinary alignment/finalization
    // orchestrator run unchanged on a bound-only transcript.
    static void normalize_for_coefficient_commitment(
        const EvalContext &context, Ciphertext &ciphertext);
    static bool correction_factor_is_one(const Ciphertext &ciphertext);
    static bool is_normalized_for_coefficient_commitment(
        const Ciphertext &ciphertext);
    static std::uint64_t partial_decryption_infinity_norm(
        const ClientContext &context, const Ciphertext &ciphertext);
    static bool partial_decryption_within_bound(
        const ClientContext &context, const Ciphertext &ciphertext,
        std::uint64_t threshold);
};

static_assert(FheBackend<NoiseEnvelopeBackend>);

} // namespace laminate::fhe

#endif // LAMINATE_FHE_NOISE_ENVELOPE_BACKEND_HPP
