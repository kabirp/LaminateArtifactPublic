#ifndef LAMINATE_FHE_SEAL_BACKEND_HPP
#define LAMINATE_FHE_SEAL_BACKEND_HPP

/// @file seal_backend.hpp
/// @brief Role-separated Microsoft SEAL BGV backend.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/noise/deterministic.hpp"
#include "laminate/transcript/hash.hpp"

#include "seal/seal.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace laminate::fhe {

struct SealParameters {
    std::size_t poly_modulus_degree = kDefaultPolyModulusDegree;
    /// Number of primes in a fresh ciphertext, excluding the special
    /// key-switching prime that SEAL removes from the data chain.
    std::size_t fresh_rns_limbs = 5;
    /// Optional exact data-prime widths, ordered from the bottom prime that
    /// survives every switch to the top prime removed first. When nonempty,
    /// its size must equal `fresh_rns_limbs`; entry zero must be 60 because
    /// the backend pins it to the native outer field. Every generated prime is
    /// 1 modulo both 2N and t, so deterministic BGV modulus switches preserve
    /// correction factor one.
    std::vector<int> data_prime_bit_sizes;
    /// Optional exact data primes in the same bottom-to-top order. This is
    /// mutually exclusive with `data_prime_bit_sizes`. Unlike generated
    /// Laminate profiles, an exact payload-only profile need not use the
    /// native outer-field modulus as its surviving bottom prime. Exact
    /// profiles are also useful when a schedule deliberately mixes
    /// correction-preserving and ordinary NTT primes.
    std::vector<std::uint64_t> exact_data_primes;
    /// Exact special key-switching prime paired with `exact_data_primes`.
    /// This must be nonzero exactly when `exact_data_primes` is nonempty.
    std::uint64_t exact_special_prime = 0;
    int bits_per_data_prime = 60;
    int special_prime_bits = 60;
    seal::sec_level_type security_level = seal::sec_level_type::tc128;
    /// Run the exact deterministic coefficient-bound rules alongside SEAL.
    /// Disabled for timing runs because this is offline certificate work, not
    /// part of the online prover.
    bool track_deterministic_noise_bounds = false;
    /// Optional cap on the exact bit length of the fresh data-modulus product.
    /// Zero disables the check. This excludes SEAL's special key-switching
    /// prime.
    std::size_t max_fresh_ciphertext_modulus_bits = 0;
    /// Optional cap on the exact key-modulus product bit length, including the
    /// special key-switching prime. Zero disables the check.
    std::size_t max_key_modulus_bits = 0;
    /// Payload-only diagnostics can omit rotation keys. Full Laminate proving
    /// requires them and therefore keeps this enabled by default.
    bool generate_galois_keys = true;

    bool operator==(const SealParameters &) const = default;
};

/// N=2^14, depth-8 profile with a 390-bit fresh data modulus and a 423-bit
/// key modulus. It uses `sec_level_type::none` and preserves correction factor
/// one across every data-prime drop. Base benchmarks and payload diagnostics
/// use this chain. Noise and privacy assumptions are documented in
/// docs/BGV_NOISE_AND_MODULUS_SWITCHING.md.
SealParameters make_depth8_diagnostic_parameters(
    bool generate_galois_keys = true);

/// Caller-owned allocation limits for the key-free verifier context bundle.
/// A byte cap alone cannot bound the SEAL parameter construction requested by
/// a compact hostile descriptor, so degree and modulus-chain limits are
/// explicit as well.
struct SealPublicVerifierContextDecodeLimits {
    std::size_t max_bundle_bytes = 0;
    std::size_t max_poly_modulus_degree = 0;
    std::size_t max_rns_limbs = 0;
};

/// Caller-owned limits for restoring the server's fixed-message-cell
/// plaintext basis.  The artifact contains raw q-NTT coefficients at every
/// data level.  Both caps are checked before any plaintext allocation.
struct SealFixedMessageCellPreprocessingDecodeLimits {
    std::size_t max_artifact_bytes = 0;
    std::size_t max_ntt_coefficient_bytes = 0;
};

/// Exact persistent representation accounting for the fixed-message-cell
/// plaintext basis.
struct SealFixedMessageCellPreprocessingMetadata {
    Digest artifact_id{};
    Digest storage_context_id{};
    std::size_t artifact_bytes = 0;
    std::size_t fixed_message_cells = 0;
    std::size_t data_levels = 0;
    std::size_t level_representations = 0;
    std::size_t ntt_coefficient_bytes = 0;

    bool operator==(
        const SealFixedMessageCellPreprocessingMetadata &) const = default;
};

class SealBackend {
  public:
    /// This low-level API represents ciphertexts only. Operations whose
    /// result is publicly known to be zero throw instead of manufacturing an
    /// encryption-of-zero sentinel. Payload and proof code must use
    /// `fhe::FheValue` whenever a value may remain public.
    enum class OperationKind : std::size_t {
        Encrypt,
        Decrypt,
        Negate,
        Add,
        Sub,
        MulNoRelin,
        Relinearize,
        AddPlain,
        MulPlainScalar,
        MulPlainVector,
        Rotate,
        ModSwitch,
        LogicalExtAdd,
        LogicalExtSub,
        LogicalExtMul,
        LogicalExtMulPlain,
        Count,
    };

    struct OperationCounts {
        using LimbBuckets = std::map<std::size_t, std::uint64_t>;
        static constexpr std::size_t kKindCount =
            static_cast<std::size_t>(OperationKind::Count);
        std::array<LimbBuckets, kKindCount> by_kind{};

        /// Public base-plaintext entry points used while counting was
        /// enabled. These report the host representation; operation buckets
        /// report the arithmetic path separately.
        std::uint64_t add_plain_scalar_api_calls = 0;
        std::uint64_t add_plain_vector_api_calls = 0;
        std::uint64_t add_plain_vector_api_elements = 0;
        std::uint64_t mul_plain_scalar_api_calls = 0;
        std::uint64_t mul_plain_vector_api_calls = 0;
        std::uint64_t mul_plain_vector_api_elements = 0;
        /// Construction and online use of immutable full-slot bases. Online
        /// calls do not allocate a SlotVector or invoke BatchEncoder/NTT.
        /// Extension bases are challenge-derived, scoped to one reduction,
        /// and own representations for exactly one source level.
        std::uint64_t prepared_extension_basis_setup_calls = 0;
        std::uint64_t prepared_extension_basis_level_representations = 0;
        std::uint64_t prepared_extension_basis_ntt_bytes_created = 0;
        std::uint64_t prepared_extension_basis_api_calls = 0;
        /// Direct promotion of one base ciphertext through a prepared
        /// extension-valued slot basis. This is distinct from multiplying an
        /// already represented extension ciphertext by that basis.
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

        const LimbBuckets &buckets(OperationKind kind) const;
        std::uint64_t calls(OperationKind kind) const;
        std::uint64_t limb_operations(OperationKind kind) const;
    };

    struct CounterState {
        bool enabled = false;
        OperationCounts counts;
    };

    /// Shared server-side cache of plaintexts already lifted to every data
    /// modulus and transformed to NTT form.  The definition stays private to
    /// the SEAL implementation; EvalContext copies share the same cache.
    struct PreparedPlaintextCache;

    class PreparedSlotBasis {
      public:
        PreparedSlotBasis() = default;

      private:
        struct Impl;
        std::shared_ptr<const Impl> impl_;
        explicit PreparedSlotBasis(std::shared_ptr<const Impl> impl)
            : impl_(std::move(impl)) {}
        friend class SealBackend;
    };

    class PreparedLevelSlotBasis {
      public:
        PreparedLevelSlotBasis() = default;

      private:
        struct Impl;
        std::shared_ptr<const Impl> impl_;
        explicit PreparedLevelSlotBasis(std::shared_ptr<const Impl> impl)
            : impl_(std::move(impl)) {}
        friend class SealBackend;
    };

    class PreparedExtensionSlotBasis {
      public:
        PreparedExtensionSlotBasis() = default;

      private:
        struct Impl;
        std::shared_ptr<const Impl> impl_;
        explicit PreparedExtensionSlotBasis(
            std::shared_ptr<const Impl> impl)
            : impl_(std::move(impl)) {}
        friend class SealBackend;
    };

    struct PlaintextPreprocessingStats {
        std::size_t logical_plaintexts = 0;
        std::size_t level_representations = 0;
        /// Raw bytes occupied by the cached q-NTT coefficient arrays. This
        /// excludes allocator and container metadata.
        std::size_t ntt_coefficient_bytes = 0;

        bool operator==(const PlaintextPreprocessingStats &) const = default;
    };

    struct Ciphertext {
        seal::Ciphertext raw;
        /// Conservative symbolic diagnostic only. The client-side invariant
        /// noise budget is authoritative for measured correctness.
        std::size_t noise_loss_bits = 0;
        /// Optional theorem-oriented coefficient bound. Unlike
        /// `noise_loss_bits`, this is an exact, fail-closed derivation from
        /// public sampler support and operation rules.
        std::optional<DeterministicNoiseBound> deterministic_noise_bound;

        std::size_t size() const { return raw.size(); }
    };

    using ExtCiphertext = ExtensionCiphertext<Ciphertext>;

    struct EvalContext {
        const SealParameters parameters;
        /// Domain-separated digest of the exact parameter description,
        /// encryption parameters, public key, relinearization keys, and
        /// Galois keys. Persistence APIs reject every other server bundle,
        /// including one with the same public key but different evaluation
        /// keys.
        const Digest storage_id{};
        const std::shared_ptr<seal::SEALContext> context;
        const std::shared_ptr<seal::BatchEncoder> encoder;
        const std::shared_ptr<seal::Evaluator> evaluator;
        const std::shared_ptr<const seal::RelinKeys> relin_keys;
        const std::shared_ptr<const seal::GaloisKeys> galois_keys;
        const std::shared_ptr<CounterState> counters;
        const std::shared_ptr<PreparedPlaintextCache> prepared_plaintexts;
        /// Retained so a caller can explicitly export a server-process
        /// bundle. It is public key material, not a decryption capability.
        const std::shared_ptr<const seal::PublicKey> public_key;

        // Identity-bound members are const and construction stays private.
        // This makes the cached storage identity safe to read per ciphertext
        // without repeatedly hashing large evaluation-key bundles.
        EvalContext(const EvalContext &) = default;
        EvalContext(EvalContext &&) = default;

      private:
        EvalContext(
            SealParameters parameters, Digest storage_id,
            std::shared_ptr<seal::SEALContext> context,
            std::shared_ptr<seal::BatchEncoder> encoder,
            std::shared_ptr<seal::Evaluator> evaluator,
            std::shared_ptr<const seal::RelinKeys> relin_keys,
            std::shared_ptr<const seal::GaloisKeys> galois_keys,
            std::shared_ptr<CounterState> counters,
            std::shared_ptr<PreparedPlaintextCache> prepared_plaintexts,
            std::shared_ptr<const seal::PublicKey> public_key)
            : parameters(std::move(parameters)), storage_id(storage_id),
              context(std::move(context)), encoder(std::move(encoder)),
              evaluator(std::move(evaluator)),
              relin_keys(std::move(relin_keys)),
              galois_keys(std::move(galois_keys)),
              counters(std::move(counters)),
              prepared_plaintexts(std::move(prepared_plaintexts)),
              public_key(std::move(public_key)) {}

        friend class SealBackend;
    };

    struct ClientContext {
        const SealParameters parameters;
        const std::shared_ptr<seal::SEALContext> context;
        const std::shared_ptr<seal::BatchEncoder> encoder;
        const std::shared_ptr<seal::Encryptor> encryptor;
        const std::shared_ptr<seal::Decryptor> decryptor;
        /// Retained only on the client side for the transcript-packing
        /// partial-decryption predicate. The public EvalContext never holds
        /// this key.
        const std::shared_ptr<const seal::SecretKey> secret_key;
        const std::shared_ptr<CounterState> counters;
        /// The complete matching server-bundle identity. This lets a caller
        /// fail closed before pairing independently loaded client and server
        /// state. On a standalone decoded client bundle it remains an encoded
        /// claim until `deserialize_context_bundles` compares the server
        /// identity, parameter description, and public key.
        const Digest storage_id{};
        /// Retained only to make the client bundle self-contained and to
        /// validate that its secret and public keys are a pair.
        const std::shared_ptr<const seal::PublicKey> public_key;

        ClientContext(const ClientContext &) = default;
        ClientContext(ClientContext &&) = default;

      private:
        ClientContext(
            SealParameters parameters,
            std::shared_ptr<seal::SEALContext> context,
            std::shared_ptr<seal::BatchEncoder> encoder,
            std::shared_ptr<seal::Encryptor> encryptor,
            std::shared_ptr<seal::Decryptor> decryptor,
            std::shared_ptr<const seal::SecretKey> secret_key,
            std::shared_ptr<CounterState> counters, Digest storage_id,
            std::shared_ptr<const seal::PublicKey> public_key)
            : parameters(std::move(parameters)), context(std::move(context)),
              encoder(std::move(encoder)), encryptor(std::move(encryptor)),
              decryptor(std::move(decryptor)),
              secret_key(std::move(secret_key)),
              counters(std::move(counters)), storage_id(storage_id),
              public_key(std::move(public_key)) {}

        friend class SealBackend;
    };

    /// Minimal public context needed to decode and verify packed proofs.
    ///
    /// It owns the exact BGV parameter context and public plaintext encoder,
    /// but no public key, evaluator key, relinearization key, Galois key,
    /// encryptor, decryptor, or secret key.  It is intentionally a distinct
    /// type from `EvalContext`: server proving APIs cannot accept this role
    /// projection merely because the underlying encryption parameters match.
    struct PublicVerifierContext {
        const SealParameters parameters;
        const Digest storage_id{};
        const std::shared_ptr<seal::SEALContext> context;
        const std::shared_ptr<seal::BatchEncoder> encoder;

        PublicVerifierContext(const PublicVerifierContext &) = default;
        PublicVerifierContext(PublicVerifierContext &&) = default;

      private:
        PublicVerifierContext(
            SealParameters parameters, Digest storage_id,
            std::shared_ptr<seal::SEALContext> context,
            std::shared_ptr<seal::BatchEncoder> encoder)
            : parameters(std::move(parameters)), storage_id(storage_id),
              context(std::move(context)), encoder(std::move(encoder)) {}

        friend class SealBackend;
    };

    struct Contexts {
        EvalContext eval;
        ClientContext client;
    };

    static Contexts create(const SealParameters &parameters = {});

    /// Project the immutable public verification capability from either role
    /// without copying or retaining evaluation/secret keys.
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
    /// Add to an owned accumulator. The right operand is never modified;
    /// same-level additions reuse the accumulator's SEAL allocation.
    /// Ordinary same-level failures leave raw data and metadata unchanged. A
    /// transparent-result invariant failure makes the accumulator unusable;
    /// callers must represent structurally public zeros above this raw API.
    /// If level alignment succeeds before a later failure, the accumulator
    /// remains at that lower level.
    static void add_assign(const EvalContext &context,
                           Ciphertext &accumulator,
                           const Ciphertext &term);
    /// Typed addition boundary. A disengaged result means `accumulator`
    /// remains encrypted; an engaged result is the public plaintext produced
    /// by exact cancellation and makes the raw accumulator unusable.
    static std::optional<SlotVector> add_assign_or_public(
        const EvalContext &context, Ciphertext &accumulator,
        const Ciphertext &term);
    /// Exact in-memory equality used by `FheValue` to keep copied
    /// cancellation public. This compares the existing SEAL representation
    /// directly and never serializes either operand.
    static bool same_ciphertext(const EvalContext &context,
                                const Ciphertext &left,
                                const Ciphertext &right);
    /// Typed subtraction boundary. An engaged result is the exact public
    /// plaintext left after correlated ciphertext components cancel.
    static std::optional<SlotVector> sub_assign_or_public(
        const EvalContext &context, Ciphertext &accumulator,
        const Ciphertext &term);
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
    /// Add a constant BGV plaintext polynomial directly, without a
    /// BatchEncoder input or slot-count-sized host vector.
    static Ciphertext add_plain_scalar(const EvalContext &context,
                                       const Ciphertext &ciphertext,
                                       const Fp &plaintext);
    static Ciphertext mul_plain(const EvalContext &context,
                                const Ciphertext &ciphertext,
                                const SlotVector &plaintext);
    /// Multiply by a constant BGV plaintext polynomial directly, without a
    /// BatchEncoder input or slot-count-sized host vector.
    static Ciphertext mul_plain_scalar(const EvalContext &context,
                                       const Ciphertext &ciphertext,
                                       const Fp &plaintext);
    static PreparedSlotBasis prepare_slot_basis(
        const EvalContext &context, const SlotVector &basis);
    static Ciphertext mul_plain_prepared(
        const EvalContext &context, const Ciphertext &ciphertext,
        const PreparedSlotBasis &basis);
    /// Prepare one SIMD plaintext at exactly `level_reference.parms_id()`.
    /// The returned handle owns the one-level NTT plaintext and never inserts
    /// it into the shared all-level preprocessing cache.
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
    /// Encode and transform one challenge-derived extension slot basis at
    /// exactly the reference ciphertext's level. The returned handle owns
    /// those representations; destroying it at the end of the reduction
    /// retires the storage instead of growing the shared all-level cache.
    static PreparedExtensionSlotBasis prepare_extension_slot_basis(
        const EvalContext &context, const Ciphertext &level_reference,
        const PlainExtension &basis);
    /// Multiply an extension ciphertext by one immutable extension-valued
    /// slot basis. Every nonconstant base coefficient is already q-NTT
    /// transformed at the handle's one bound ciphertext level, so the online
    /// call performs no host-vector construction, cache hashing,
    /// BatchEncoder work, or NTT.
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

    /// Prepare one public SIMD plaintext for all data-chain levels.  Later
    /// `mul_plain` calls with the same slots use the cached NTT representation
    /// and perform only the coefficientwise products.  Returns false when the
    /// plaintext was already present.
    static bool preprocess_plaintext(const EvalContext &context,
                                     const SlotVector &plaintext);
    static PlaintextPreprocessingStats plaintext_preprocessing_stats(
        const EvalContext &context);
    static Ciphertext rotate(const EvalContext &context,
                             const Ciphertext &ciphertext, std::size_t steps);
    static Ciphertext fold(const EvalContext &context,
                           const Ciphertext &ciphertext);

    static ExtCiphertext ext_add(const EvalContext &context,
                                 const ExtCiphertext &left,
                                 const ExtCiphertext &right);
    static void ext_add_assign(const EvalContext &context,
                               ExtCiphertext &accumulator,
                               const ExtCiphertext &term);
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
    /// Plaintext modulus used by the public BatchEncoder.
    static std::uint64_t plaintext_modulus(const EvalContext &context);
    /// Encode SIMD slots exactly as `mul_plain` does and expose the centered
    /// plaintext-polynomial coefficients. This is a public-parameter
    /// diagnostic used by transcript-packing no-wrap analysis; it uses no
    /// secret key and performs no ciphertext operation.
    static std::vector<std::int64_t> encode_centered_plaintext_coefficients(
        const EvalContext &context, const SlotVector &slots);
    static std::vector<std::int64_t> encode_centered_plaintext_coefficients(
        const PublicVerifierContext &context, const SlotVector &slots);
    /// Convert one centered coefficient polynomial back to the SIMD slots
    /// whose ordinary BatchEncoder encoding is exactly that polynomial.
    /// This lets signed-digit packing use small coefficient polynomials while
    /// continuing through the backend's ordinary plaintext multiplication.
    static SlotVector decode_centered_plaintext_coefficients(
        const EvalContext &context,
        std::span<const std::int64_t> centered_coefficients);
    static SlotVector decode_centered_plaintext_coefficients(
        const PublicVerifierContext &context,
        std::span<const std::int64_t> centered_coefficients);
    /// The single data prime at the bottom of this context's modulus chain.
    static std::uint64_t lowest_coefficient_modulus(
        const EvalContext &context);

    /// Canonicalize a size-two, one-prime, NTT-form BGV ciphertext to
    /// correction factor one. Reject every other representation.
    ///
    /// The operation preserves every decrypted slot. A coefficient
    /// commitment and every linear relation proved about it must use this
    /// representation; otherwise raw coefficient addition does not match BGV
    /// plaintext addition across differing correction factors.
    static void normalize_for_coefficient_commitment(
        const EvalContext &context, Ciphertext &ciphertext);
    /// Whether the BGV correction-factor metadata alone is one. This is
    /// meaningful before the ciphertext reaches the commitment level.
    static bool correction_factor_is_one(const Ciphertext &ciphertext);
    /// Whether the complete coefficient-commitment representation is
    /// canonical: size two, one prime, NTT form, and correction factor one.
    static bool is_normalized_for_coefficient_commitment(
        const Ciphertext &ciphertext);

    /// Expose the exact component-major NTT coordinates committed by the
    /// outer packing relation. The ciphertext must already be canonical:
    /// size two, one data prime, NTT form, and correction factor one.
    /// The borrowed view is invalidated by ciphertext mutation or movement.
    static std::span<const std::uint64_t>
    coefficient_commitment_ntt_coordinate_view(
        const Ciphertext &ciphertext);

    /// Owning diagnostic counterpart of the borrowed coordinate view.
    static std::vector<std::uint64_t>
    coefficient_commitment_ntt_coordinates(const Ciphertext &ciphertext);

    /// Lift one centered plaintext polynomial to the bottom data prime and
    /// return the exact NTT multiplier used by SEAL's `multiply_plain` path.
    /// This is public preprocessing and performs no ciphertext operation.
    static std::vector<std::uint64_t>
    encode_lowest_plaintext_ntt_coordinates(
        const EvalContext &context,
        std::span<const std::int64_t> centered_coefficients);
    static std::vector<std::uint64_t>
    encode_lowest_plaintext_ntt_coordinates(
        const PublicVerifierContext &context,
        std::span<const std::int64_t> centered_coefficients);

    /// Return the centered coefficients of `c0 + c1*s` at the canonical
    /// one-prime commitment boundary. This secret-key diagnostic makes the
    /// exact signed plaintext-lift behavior testable.
    static std::vector<std::int64_t>
    partial_decryption_centered_coefficients(
        const ClientContext &context, const Ciphertext &ciphertext);

    /// Return `|centered(c0 + c1*s)|_infinity` in the coefficient basis.
    ///
    /// This is the exact client-side predicate used by the well-formedness
    /// tests. It requires a normalized, size-two, NTT-form ciphertext at the
    /// single-prime bottom level. It is a diagnostic/checking primitive, not
    /// a public honest-noise certificate.
    static std::uint64_t partial_decryption_infinity_norm(
        const ClientContext &context, const Ciphertext &ciphertext);

    /// Exact infinity norm of the canonical BGV error `e` in
    /// `c0 + c1*s = m + t*e` at the normalized one-prime boundary. This is a
    /// secret-key benchmark diagnostic, not a server-side scheduling input.
    static std::uint64_t canonical_error_infinity_norm(
        const EvalContext &eval, const ClientContext &client,
        const Ciphertext &ciphertext);
    static std::uint64_t canonical_error_infinity_norm(
        const PublicVerifierContext &verifier, const ClientContext &client,
        const Ciphertext &ciphertext);
    /// Exact norm of `(c0 + public_c0) + c1*s` at the normalized bottom
    /// level. `ciphertext == nullptr` denotes a wholly public value. The
    /// public c1 component is identically zero and is never materialized.
    static std::uint64_t
    partial_decryption_with_public_ntt_offset_infinity_norm(
        const ClientContext &context, const Ciphertext *ciphertext,
        std::span<const std::uint64_t> public_c0_coordinates);
    static bool partial_decryption_within_bound(
        const ClientContext &context, const Ciphertext &ciphertext,
        std::uint64_t threshold);

    static std::vector<std::uint8_t>
    serialize(const Ciphertext &ciphertext);
    /// Strict inverse of the uncompressed SEAL encoding used in canonical
    /// protocol proofs. The supplied evaluation context authenticates the
    /// encryption parameters but provides no decryption capability.
    static Ciphertext deserialize_protocol(
        const EvalContext &context,
        std::span<const std::uint8_t> bytes);
    static Ciphertext deserialize_protocol(
        const PublicVerifierContext &context,
        std::span<const std::uint8_t> bytes);
    static Digest storage_context_id(const EvalContext &context);
    static Digest storage_context_id(const ClientContext &context);
    static Digest storage_context_id(
        const PublicVerifierContext &context);
    static std::uint64_t
    storage_ciphertext_byte_limit(const EvalContext &context);

    /// Canonical, versioned byte bundle for a fresh server process. The
    /// bundle contains exact BGV parameters, the public key, relinearization
    /// keys, and (when enabled) Galois keys. It never contains a secret key.
    static std::vector<std::uint8_t>
    serialize_evaluation_context_bundle(const EvalContext &context);
    static EvalContext deserialize_evaluation_context_bundle(
        std::span<const std::uint8_t> bytes);

    /// Canonical server-only artifact containing the already transformed
    /// fixed-message-cell masks at every data level. Mask preprocessing and
    /// evaluation keys use separate persistence artifacts.
    /// Setup must commit the domain-separated artifact ID alongside the
    /// bytes; restoration requires that independently authenticated ID.
    static std::vector<std::uint8_t>
    serialize_fixed_message_cell_preprocessing(
        const EvalContext &context);
    static Digest fixed_message_cell_preprocessing_artifact_id(
        std::span<const std::uint8_t> bytes);
    /// Install one exact basis into a freshly restored, otherwise empty
    /// evaluation cache.  The artifact is bound to the context's complete
    /// storage identity and to the canonical 16 fixed cell masks. No
    /// BatchEncoder or NTT work is performed during restoration.
    static SealFixedMessageCellPreprocessingMetadata
    restore_fixed_message_cell_preprocessing(
        const EvalContext &context,
        std::span<const std::uint8_t> bytes,
        const Digest &expected_artifact_id,
        const SealFixedMessageCellPreprocessingDecodeLimits &limits);

    /// Canonical, versioned byte bundle for client-private state. This bundle
    /// contains the secret key and must be protected by the caller. No path is
    /// selected implicitly; callers own storage and transport policy.
    static std::vector<std::uint8_t>
    serialize_client_context_bundle(const ClientContext &context);
    static ClientContext deserialize_client_context_bundle(
        std::span<const std::uint8_t> bytes);

    /// Reload independently stored role bundles and require their immutable
    /// context identities to agree.
    static Contexts deserialize_context_bundles(
        std::span<const std::uint8_t> evaluation_bundle,
        std::span<const std::uint8_t> client_bundle);

    /// Canonical key-free verifier bundle.  Restoration requires both an
    /// explicit byte cap and the independently authenticated server-bundle
    /// identity; the bundle cannot turn an unauthenticated identity claim
    /// into trusted preprocessing.
    static std::vector<std::uint8_t>
    serialize_public_verifier_context_bundle(
        const PublicVerifierContext &context);
    static PublicVerifierContext
    deserialize_public_verifier_context_bundle(
        std::span<const std::uint8_t> bytes,
        const Digest &expected_storage_id,
        const SealPublicVerifierContextDecodeLimits &limits);
    /// Versioned, lossless encoding for external-memory trace storage.
    /// Exact deterministic-noise certificates are deliberately unsupported:
    /// serializing a ciphertext carrying one fails instead of dropping it.
    static std::vector<std::uint8_t>
    serialize_for_storage(const EvalContext &context,
                          const Ciphertext &ciphertext);
    static void append_storage_serialization(
        const EvalContext &context, const Ciphertext &ciphertext,
        std::vector<std::uint8_t> &output);
    /// The same canonical ciphertext envelope from client-owned state. This
    /// requires only the matching encryption parameters and public storage
    /// identity; it does not require server evaluation keys.
    static std::vector<std::uint8_t>
    serialize_for_storage(const ClientContext &context,
                          const Ciphertext &ciphertext);
    static std::vector<std::uint8_t>
    serialize_for_storage(const PublicVerifierContext &context,
                          const Ciphertext &ciphertext);
    static Ciphertext deserialize_from_storage(
        const EvalContext &context, std::span<const std::uint8_t> bytes);
    static Ciphertext deserialize_from_storage(
        const ClientContext &context, std::span<const std::uint8_t> bytes);
    static Ciphertext deserialize_from_storage(
        const PublicVerifierContext &context,
        std::span<const std::uint8_t> bytes);
    /// Decode a record already validated by `deserialize_from_storage` during
    /// private-artifact open, or emitted canonically by this process. This
    /// retains envelope, context, length, and SEAL structural validation while
    /// skipping redundant coefficient-range validation and canonical
    /// reserialization.
    static Ciphertext deserialize_validated_private_storage(
        const EvalContext &context, std::span<const std::uint8_t> bytes);

    static int invariant_noise_budget(const ClientContext &context,
                                      const Ciphertext &ciphertext);
    static std::vector<std::uint64_t>
    coefficient_moduli(const EvalContext &context);
    /// Data primes present in this ciphertext, ordered `[q_0,...,q_l]`.
    /// Unlike `coefficient_moduli`, this excludes the special key-switching
    /// prime and reflects the ciphertext's current level.
    static std::vector<std::uint64_t> data_coefficient_moduli(
        const EvalContext &context, const Ciphertext &ciphertext);
    /// The same current-level data-prime query from the client role. This is
    /// useful for secret-key-assisted diagnostics after a response has been
    /// received; it does not require server evaluation keys.
    static std::vector<std::uint64_t> data_coefficient_moduli(
        const ClientContext &context, const Ciphertext &ciphertext);
    /// Exact bit length of the data-modulus product on a fresh ciphertext.
    static std::size_t fresh_ciphertext_modulus_bits(
        const EvalContext &context);
    /// Sum of the individual fresh data-prime bit widths. This conservative
    /// ledger can exceed the product bit length by a few bits.
    static std::size_t fresh_ciphertext_modulus_width_sum_bits(
        const EvalContext &context);
    /// Exact bit length of the key-modulus product, including the special
    /// prime.
    static std::size_t key_modulus_bits(const EvalContext &context);
    /// Sum of the individual key-prime bit widths.
    static std::size_t key_modulus_width_sum_bits(
        const EvalContext &context);

    static void reset_counts(const EvalContext &context);
    static void set_counting(const EvalContext &context, bool enabled);
    static OperationCounts counts(const EvalContext &context);
    static const char *operation_name(OperationKind kind);
};

static_assert(FheBackend<SealBackend>);

} // namespace laminate::fhe

#endif // LAMINATE_FHE_SEAL_BACKEND_HPP
