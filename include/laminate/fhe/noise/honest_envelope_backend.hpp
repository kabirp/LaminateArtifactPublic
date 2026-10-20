#ifndef LAMINATE_FHE_NOISE_HONEST_ENVELOPE_BACKEND_HPP
#define LAMINATE_FHE_NOISE_HONEST_ENVELOPE_BACKEND_HPP

/// @file honest_envelope_backend.hpp
/// @brief Honest-input operational error envelope for Base proof arithmetic.
///
/// This backend carries a canonical BGV error bound and an RNS level, but no
/// ciphertext value. Its fixed operation debits are setup inputs obtained
/// outside this component. It is an engineering model for honestly generated
/// ciphertexts, not the adversarial deterministic-noise theorem.
///
/// Structural padding and publicly known zero extension coordinates are not
/// ciphertext states. They are represented outside this base-ciphertext model
/// and incur no operation debit. The backend's private exact-cancellation
/// fallback instead models a concrete base ciphertext whose value is zero;
/// that case can arise from cancellation of private encrypted values.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/noise/deterministic.hpp"
#include "laminate/transcript/hash.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace laminate::fhe {

/// Largest supported fixed operation debit in the honest-input envelope.
inline constexpr std::size_t kMaximumHonestNoiseEnvelopeDebitBits = 4096;

/// Setup-bound inputs to the honest-input operational model.
struct HonestNoiseEnvelopeParameters {
    std::size_t ring_degree = 0;
    std::uint64_t plaintext_modulus = 0;
    NaturalMagnitude fresh_canonical_error_bound;
    /// One calibrated debit for CT--CT multiplication plus relinearization.
    /// It is charged by `mul_no_relin`; `relinearize` only changes shape.
    std::size_t ctct_relinearized_debit_bits = 0;
    std::size_t plaintext_multiplication_debit_bits = 0;
    std::size_t rotation_debit_bits = 0;
    NaturalMagnitude switch_rounding_error_bound;
    /// Data primes in chain order `[q_0,...,q_L]`. A switch drops the final
    /// active entry.
    std::vector<std::uint64_t> data_moduli;

    void validate() const;

    bool operator==(const HonestNoiseEnvelopeParameters &) const = default;
};

/// Canonical v1 encoding of every setup-bound envelope parameter.
/// Parameters are validated before encoding; vector order is preserved.
std::vector<std::uint8_t>
encode_canonical(const HonestNoiseEnvelopeParameters &parameters);

/// SHA-256 of `encode_canonical(parameters)`.
Digest honest_noise_envelope_parameters_digest(
    const HonestNoiseEnvelopeParameters &parameters);

enum class HonestNoiseEnvelopeOperation : std::uint8_t {
    SourceCiphertext,
    FreshEncryption,
    Negation,
    Addition,
    Subtraction,
    PlaintextAddition,
    PlaintextMultiplication,
    CiphertextMultiplication,
    Relinearization,
    Rotation,
    ModulusSwitch,
};

const char *honest_noise_envelope_operation_name(
    HonestNoiseEnvelopeOperation operation);

/// First failed phase-fit check in one ciphertext's derivation.
struct HonestNoiseEnvelopeFailure {
    HonestNoiseEnvelopeOperation operation =
        HonestNoiseEnvelopeOperation::SourceCiphertext;
    std::uint64_t operation_sequence = 0;
    std::size_t input_rns_limbs = 0;
    std::size_t output_rns_limbs = 0;
    NaturalMagnitude canonical_error_bound;
    std::size_t active_modulus_product_bits = 0;

    bool operator==(const HonestNoiseEnvelopeFailure &) const = default;
};

/// Return `t*beta + (t-1)/2`, the partial-decryption phase bound associated
/// with canonical error `beta`.
NaturalMagnitude honest_noise_phase_bound(
    std::uint64_t plaintext_modulus,
    const NaturalMagnitude &canonical_error_bound);

/// Exact strict BGV phase-fit predicate:
///
///   2 * (t*beta + (t-1)/2) < product(active_data_moduli).
bool honest_noise_fits_active_modulus(
    std::uint64_t plaintext_modulus,
    const NaturalMagnitude &canonical_error_bound,
    std::span<const std::uint64_t> active_data_moduli);

/// Exact state of one extension coefficient around a canonical Base-message
/// normalization. These are semantically live proof values only; structural
/// padding never reaches the normalization helper or this record.
struct HonestBaseNormalizationCoefficientRecord {
    /// False only when the corresponding extension coordinate is the
    /// protocol's public algebraic zero and therefore has no ciphertext.
    bool present = false;
    NaturalMagnitude input_canonical_error_bound;
    NaturalMagnitude output_canonical_error_bound;
    std::size_t input_rns_limbs = 0;
    std::size_t output_rns_limbs = 0;
    std::size_t input_component_count = 0;
    std::size_t output_component_count = 0;
    std::uint64_t input_identity = 0;
    std::uint64_t output_identity = 0;
    std::optional<HonestNoiseEnvelopeFailure> input_first_failure;
    std::optional<HonestNoiseEnvelopeFailure> output_first_failure;

    bool operator==(
        const HonestBaseNormalizationCoefficientRecord &) const = default;
};

/// One record per call to Base's canonical extension-message normalizer.
/// Entries whose `present` flag is false preserve a symbolic public-zero
/// coordinate; they do not stand for an encrypted zero.
struct HonestBaseNormalizationRecord {
    std::array<HonestBaseNormalizationCoefficientRecord,
               kExtensionDegree>
        coefficients;

    bool operator==(const HonestBaseNormalizationRecord &) const = default;
};

/// Value-free FHE backend for the challenge-independent Base proof topology.
class HonestNoiseEnvelopeBackend {
  public:
    struct SequenceState;

    struct Ciphertext {
        NaturalMagnitude canonical_error_bound;
        std::size_t rns_limbs = 0;
        std::size_t component_count = 2;
        std::uint64_t identity = 0;
        /// Shared opaque owner token. Numeric ciphertext identities are only
        /// meaningful within this exact backend context.
        std::shared_ptr<SequenceState> context_token;
        std::size_t operation_count = 0;
        std::uint64_t last_operation_sequence = 0;
        std::optional<HonestNoiseEnvelopeFailure> first_failure;

        std::size_t size() const { return component_count; }
        bool all_phases_fit() const {
            return !first_failure.has_value();
        }
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

    struct SequenceState {
        explicit SequenceState(HonestNoiseEnvelopeParameters parameters)
            : bound_parameters(std::move(parameters)) {}

        const HonestNoiseEnvelopeParameters bound_parameters;
        std::uint64_t next_identity = 1;
        std::uint64_t next_operation = 1;
        std::vector<HonestBaseNormalizationRecord>
            base_normalization_records;
    };

    struct EvalContext {
        HonestNoiseEnvelopeParameters parameters;
        std::shared_ptr<SequenceState> sequences;
    };

    struct ClientContext {
        HonestNoiseEnvelopeParameters parameters;
        std::shared_ptr<SequenceState> sequences;
    };

    struct Contexts {
        EvalContext eval;
        ClientContext client;
    };

    static Contexts create(HonestNoiseEnvelopeParameters parameters);

    /// Import one semantically live trace value at its schedule-derived bound
    /// and level. A zero bound is rejected: public structural zero must remain
    /// outside the ciphertext topology.
    static Ciphertext source_ciphertext(
        const EvalContext &context, NaturalMagnitude canonical_error_bound,
        std::size_t rns_limbs, std::size_t component_count = 2);

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
    static Ciphertext add_plain_scalar(const EvalContext &context,
                                       const Ciphertext &ciphertext,
                                       const Fp &plaintext);
    static Ciphertext mul_plain(const EvalContext &context,
                                const Ciphertext &ciphertext,
                                const SlotVector &plaintext);
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
    static std::uint64_t plaintext_modulus(const EvalContext &context);
    static std::vector<std::uint8_t>
    serialize(const Ciphertext &ciphertext);

    static NaturalMagnitude phase_bound(const EvalContext &context,
                                        const Ciphertext &ciphertext);
    static bool fits_active_modulus(const EvalContext &context,
                                    const Ciphertext &ciphertext);

    /// Optional hook consumed by Base's generic normalization helper.
    static void observe_base_message_normalization(
        const EvalContext &context, const ExtCiphertext &before,
        const ExtCiphertext &after);
    static std::span<const HonestBaseNormalizationRecord>
    base_message_normalization_records(const EvalContext &context);
    static void clear_base_message_normalization_records(
        const EvalContext &context);

    static bool forces_challenge_independent_topology(
        const EvalContext &) {
        return true;
    }
};

static_assert(FheBackend<HonestNoiseEnvelopeBackend>);

} // namespace laminate::fhe

#endif // LAMINATE_FHE_NOISE_HONEST_ENVELOPE_BACKEND_HPP
