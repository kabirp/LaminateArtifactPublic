#ifndef LAMINATE_FHE_MOCK_BACKEND_HPP
#define LAMINATE_FHE_MOCK_BACKEND_HPP

/// @file mock_backend.hpp
/// @brief Exact slot-vector backend with FHE scheduling diagnostics.
///
/// Ciphertexts contain their plaintext slots directly. This backend checks
/// algebra, protocol wiring, and operation accounting; it supplies neither
/// encryption privacy nor measurements of real SEAL noise or FHE performance.

#include "laminate/fhe/backend.hpp"
#include "laminate/transcript/hash.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace laminate::fhe {

struct OperationCounts {
    std::uint64_t encrypt = 0;
    std::uint64_t decrypt = 0;
    std::uint64_t negate = 0;
    std::uint64_t add = 0;
    std::uint64_t sub = 0;
    std::uint64_t mul_no_relin = 0;
    std::uint64_t relinearize = 0;
    std::uint64_t add_plain = 0;
    std::uint64_t mul_plain_scalar = 0;
    std::uint64_t mul_plain_vector = 0;
    /// Host representations used by the plaintext entry points. These are
    /// distinct from the arithmetic cost classes above: a uniform SlotVector
    /// still enters through a vector API.
    std::uint64_t add_plain_scalar_api_calls = 0;
    std::uint64_t add_plain_vector_api_calls = 0;
    /// Number of Fp elements supplied to vector addition calls.
    std::uint64_t add_plain_vector_api_elements = 0;
    std::uint64_t mul_plain_scalar_api_calls = 0;
    std::uint64_t mul_plain_vector_api_calls = 0;
    /// Number of Fp elements supplied to vector multiplication calls.
    std::uint64_t mul_plain_vector_api_elements = 0;
    std::uint64_t prepared_extension_basis_setup_calls = 0;
    std::uint64_t prepared_extension_basis_api_calls = 0;
    /// Direct promotion of one base ciphertext through a prepared
    /// extension-valued slot basis. This replaces one logical dense
    /// extension plaintext multiplication.
    std::uint64_t prepared_extension_promotion_api_calls = 0;
    std::uint64_t prepared_extension_basis_avoided_vector_elements = 0;
    std::uint64_t prepared_extension_basis_avoided_batch_encodes = 0;
    std::uint64_t prepared_base_basis_setup_calls = 0;
    std::uint64_t prepared_base_basis_level_representations = 0;
    std::uint64_t prepared_base_basis_ntt_bytes_created = 0;
    std::uint64_t prepared_base_basis_api_calls = 0;
    std::uint64_t prepared_base_basis_avoided_vector_elements = 0;
    std::uint64_t prepared_base_basis_avoided_batch_encodes = 0;
    std::uint64_t fixed_message_basis_setup_calls = 0;
    std::uint64_t fixed_message_basis_api_calls = 0;
    std::uint64_t fixed_message_basis_avoided_vector_elements = 0;
    std::uint64_t fixed_message_basis_avoided_batch_encodes = 0;
    std::uint64_t fixed_message_basis_avoided_hash_probes = 0;
    std::uint64_t rotate = 0;
    std::uint64_t mod_switch = 0;
    std::uint64_t logical_ext_add = 0;
    std::uint64_t logical_ext_sub = 0;
    std::uint64_t logical_ext_mul = 0;
    std::uint64_t logical_ext_mul_plain = 0;
};

struct MockParameters {
    std::size_t slot_count = 0;
    std::size_t fresh_rns_limbs = 5;
    std::size_t bits_per_limb = 60;
    std::size_t initial_noise_margin_bits = 20;
    std::size_t rotation_noise_bits = 1;
    std::size_t relinearization_noise_bits = 2;
};

class MockBackend {
  public:
    struct Ciphertext {
        SlotVector slots;
        std::size_t rns_limbs = 0;
        bool relinearized = true;
        std::size_t depth_half_levels = 0;
        std::size_t noise_loss_bits = 0;
        /// Formal native-Q component-major coordinates used only by the
        /// packing-R1CS integration tests. Empty before canonicalization.
        std::vector<std::uint64_t> coefficient_commitment_coordinates;
        /// Opaque provenance for recognizing a copied ciphertext without
        /// comparing its private plaintext. Backend operations assign a
        /// fresh identity; ordinary C++ copies deliberately retain it.
        std::uint64_t identity = 0;
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

    struct EvalContext {
        MockParameters parameters;
        std::shared_ptr<OperationCounts> counters;
        /// Circuit-independent one-hot message masks, prepared once by
        /// server setup and reused by every Folded/Laned round.
        std::shared_ptr<std::vector<PreparedSlotBasis>> fixed_message_bases;
    };

    struct ClientContext {
        MockParameters parameters;
        std::shared_ptr<OperationCounts> counters;
    };

    /// Public, verification-only projection of the backend context.
    ///
    /// This type deliberately has neither operation counters nor the
    /// server's prepared-plaintext state.  More importantly, it is not an
    /// `EvalContext`, so payload/GKR/packing prover entry points cannot
    /// accept it accidentally.  The mock has no keys, but retaining the same
    /// role boundary as the real backend keeps process-lifecycle tests honest.
    struct PublicVerifierContext {
        const MockParameters parameters;

        PublicVerifierContext(const PublicVerifierContext &) = default;
        PublicVerifierContext(PublicVerifierContext &&) = default;

      private:
        explicit PublicVerifierContext(MockParameters parameters)
            : parameters(std::move(parameters)) {}

        friend class MockBackend;
    };

    struct Contexts {
        EvalContext eval;
        ClientContext client;
    };

    static Contexts create(const MockParameters &parameters);

    static PublicVerifierContext make_public_verifier_context(
        const EvalContext &context);
    static PublicVerifierContext make_public_verifier_context(
        const ClientContext &context);

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
    /// Add one scalar to every encrypted slot without constructing a
    /// slot-count-sized plaintext vector.
    static Ciphertext add_plain_scalar(const EvalContext &context,
                                       const Ciphertext &ciphertext,
                                       const Fp &plaintext);
    static Ciphertext mul_plain(const EvalContext &context,
                                const Ciphertext &ciphertext,
                                const SlotVector &plaintext);
    /// Multiply every encrypted slot by one scalar without constructing a
    /// slot-count-sized plaintext vector.
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
    static ExtCiphertext promote_plain_prepared_untracked(
        const EvalContext &context, const Ciphertext &ciphertext,
        const PreparedExtensionSlotBasis &basis);
    static PreparedBasisStorageStats prepared_extension_slot_basis_storage(
        const PreparedExtensionSlotBasis &basis);
    static Ciphertext rotate(const EvalContext &context,
                             const Ciphertext &ciphertext, std::size_t steps);
    static Ciphertext fold(const EvalContext &context,
                           const Ciphertext &ciphertext);

    static ExtCiphertext ext_add(const EvalContext &context,
                                 const ExtCiphertext &left,
                                 const ExtCiphertext &right);
    static void record_logical_extension_add(
        const EvalContext &context, const Ciphertext &encrypted_anchor);
    static ExtCiphertext ext_sub(const EvalContext &context,
                                 const ExtCiphertext &left,
                                 const ExtCiphertext &right);
    static void record_logical_extension_sub(
        const EvalContext &context, const Ciphertext &encrypted_anchor);
    static void record_logical_extension_mul_plain(
        const EvalContext &context, const Ciphertext &encrypted_anchor);
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
    /// Extension multiplication by one value replicated across all slots.
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
    static std::size_t rns_limb_count(
        const PublicVerifierContext &context,
        const Ciphertext &ciphertext);
    static std::size_t coeff_modulus_bits(const EvalContext &context,
                                          const Ciphertext &ciphertext);
    static int estimated_noise_bits(const EvalContext &context,
                                    const Ciphertext &ciphertext);

    static std::size_t slot_count(const EvalContext &context);
    static std::size_t slot_count(const ClientContext &context);
    static std::size_t slot_count(const PublicVerifierContext &context);
    /// Plaintext modulus used by the public coefficient encoder.
    static std::uint64_t plaintext_modulus(const EvalContext &context);
    static std::vector<std::uint8_t>
    serialize(const Ciphertext &ciphertext);
    /// Strict inverse of `serialize` at a public proof/wire trust boundary;
    /// noncanonical encodings are rejected.
    /// Diagnostic-only state omitted by the canonical protocol encoding is
    /// reconstructed conservatively; normalized one-prime coordinates are
    /// derived without performing an FHE operation.
    static Ciphertext deserialize_protocol(
        const EvalContext &context,
        std::span<const std::uint8_t> bytes);
    static Ciphertext deserialize_protocol(
        const PublicVerifierContext &context,
        std::span<const std::uint8_t> bytes);
    /// Public persistence identity for this key-free backend. It binds the
    /// complete Mock parameter profile.
    static Digest storage_context_id(const EvalContext &context);
    static Digest storage_context_id(const ClientContext &context);
    static Digest storage_context_id(
        const PublicVerifierContext &context);
    static std::uint64_t
    storage_ciphertext_byte_limit(const EvalContext &context);
    static std::vector<std::uint8_t>
    serialize_for_storage(const PublicVerifierContext &context,
                          const Ciphertext &ciphertext);
    static Ciphertext deserialize_from_storage(
        const PublicVerifierContext &context,
        std::span<const std::uint8_t> bytes);
    /// Versioned, lossless encoding for external-memory trace storage.
    static std::vector<std::uint8_t>
    serialize_for_storage(const EvalContext &context,
                          const Ciphertext &ciphertext);
    static void append_storage_serialization(
        const EvalContext &context, const Ciphertext &ciphertext,
        std::vector<std::uint8_t> &output);
    static std::vector<std::uint8_t>
    serialize_for_storage(const ClientContext &context,
                          const Ciphertext &ciphertext);
    static Ciphertext deserialize_from_storage(
        const EvalContext &context, std::span<const std::uint8_t> bytes);
    static Ciphertext deserialize_from_storage(
        const ClientContext &context,
        std::span<const std::uint8_t> bytes);

    // Exact functional hooks for transcript-packing tests. The mock treats
    // SIMD slots as plaintext coefficients; real coefficient growth is
    // exercised by SealBackend and NoiseEnvelopeBackend instead.
    static std::vector<std::int64_t> encode_centered_plaintext_coefficients(
        const EvalContext &context, const SlotVector &slots);
    static std::vector<std::int64_t> encode_centered_plaintext_coefficients(
        const PublicVerifierContext &context, const SlotVector &slots);
    static SlotVector decode_centered_plaintext_coefficients(
        const EvalContext &context,
        std::span<const std::int64_t> centered_coefficients);
    static SlotVector decode_centered_plaintext_coefficients(
        const PublicVerifierContext &context,
        std::span<const std::int64_t> centered_coefficients);
    static std::uint64_t lowest_coefficient_modulus(
        const EvalContext &context);
    static std::vector<std::uint64_t>
    encode_lowest_plaintext_ntt_coordinates(
        const EvalContext &context,
        std::span<const std::int64_t> centered_coefficients);
    static std::vector<std::uint64_t>
    encode_lowest_plaintext_ntt_coordinates(
        const PublicVerifierContext &context,
        std::span<const std::int64_t> centered_coefficients);
    static void normalize_for_coefficient_commitment(
        const EvalContext &context, Ciphertext &ciphertext);
    static bool is_normalized_for_coefficient_commitment(
        const Ciphertext &ciphertext);
    static std::span<const std::uint64_t>
    coefficient_commitment_ntt_coordinate_view(
        const Ciphertext &ciphertext);
    static std::uint64_t partial_decryption_infinity_norm(
        const ClientContext &context, const Ciphertext &ciphertext);
    static std::uint64_t
    partial_decryption_with_public_ntt_offset_infinity_norm(
        const ClientContext &context, const Ciphertext *ciphertext,
        std::span<const std::uint64_t> public_c0_coordinates);
    static bool partial_decryption_within_bound(
        const ClientContext &context, const Ciphertext &ciphertext,
        std::uint64_t threshold);

    static const OperationCounts &counts(const EvalContext &context);
    static void reset_counts(const EvalContext &context);
};

static_assert(FheBackend<MockBackend>);

} // namespace laminate::fhe

#endif // LAMINATE_FHE_MOCK_BACKEND_HPP
