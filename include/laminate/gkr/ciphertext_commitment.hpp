#ifndef LAMINATE_GKR_CIPHERTEXT_COMMITMENT_HPP
#define LAMINATE_GKR_CIPHERTEXT_COMMITMENT_HPP

/// @file ciphertext_commitment.hpp
/// @brief Typed commitment relations used by packed Folded/Laned transcripts.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/value.hpp"
#include "laminate/crypto/poseidon.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <variant>
#include <vector>

namespace laminate::gkr {

/// Versioned ciphertext-commitment relation selected during preprocessing.
///
/// `DiagnosticSimpleCtHashV2` deliberately provides no collision-resistance
/// claim. It exists only to exercise the complete quick orchestration
/// with a sparse linear circuit.  Security-bearing setups must use
/// `PoseidonV2`.
enum class CiphertextCommitmentRelation : std::uint8_t {
    PoseidonV2 = 3,
    DiagnosticSimpleCtHashV2 = 4,
};

struct CiphertextCommitmentPolicy {
    CiphertextCommitmentRelation relation =
        CiphertextCommitmentRelation::PoseidonV2;

    static constexpr CiphertextCommitmentPolicy poseidon_v2() {
        return {CiphertextCommitmentRelation::PoseidonV2};
    }

    static constexpr CiphertextCommitmentPolicy
    diagnostic_simple_ct_hash_v2() {
        return {CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2};
    }

    constexpr bool is_diagnostic_only() const {
        return relation ==
               CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2;
    }

    constexpr std::uint64_t wire_code() const {
        return static_cast<std::uint64_t>(relation);
    }

    constexpr void validate() const {
        switch (relation) {
        case CiphertextCommitmentRelation::PoseidonV2:
        case CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2:
            return;
        }
        throw std::invalid_argument(
            "unknown ciphertext-commitment relation policy");
    }

    static constexpr CiphertextCommitmentPolicy from_wire_code(
        std::uint64_t code) {
        switch (code) {
        case static_cast<std::uint64_t>(
            CiphertextCommitmentRelation::PoseidonV2):
            return poseidon_v2();
        case static_cast<std::uint64_t>(
            CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2):
            return diagnostic_simple_ct_hash_v2();
        default:
            throw std::invalid_argument(
                "unknown ciphertext-commitment relation wire code");
        }
    }

    bool operator==(const CiphertextCommitmentPolicy &) const = default;
};

inline constexpr std::string_view ciphertext_commitment_relation_name(
    CiphertextCommitmentPolicy policy) {
    policy.validate();
    switch (policy.relation) {
    case CiphertextCommitmentRelation::PoseidonV2:
        return "poseidon/v2";
    case CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2:
        return "simpleCTHash/v2";
    }
    throw std::logic_error("unreachable ciphertext-commitment relation");
}

/// Public constants for the diagnostic sparse linear relation.  The complete
/// canonical preimage is folded as `s_{i+1} = alpha*s_i + x_i`; the six
/// public fields are domain-separated affine functions of the final state.
/// These values are protocol constants and are included in the structured
/// circuit identity.
inline constexpr std::uint64_t kDiagnosticSimpleCtHashAlpha =
    0x0c616d696e617465ULL;
inline constexpr std::uint64_t kDiagnosticSimpleCtHashInitialState =
    0x03696d706c654354ULL;
inline constexpr std::array<std::uint64_t, kPoseidonDigestElements>
    kDiagnosticSimpleCtHashOutputDomains{
        0x084153482f763201ULL,
        0x084153482f763202ULL,
        0x084153482f763203ULL,
        0x084153482f763204ULL,
        0x084153482f763205ULL,
        0x084153482f763206ULL,
    };

inline constexpr std::size_t kCiphertextCommitmentMetadataElements = 4;
inline constexpr std::uint64_t kCiphertextCommitmentComponents = 2;
inline constexpr std::uint64_t kCiphertextCommitmentNttFlag = 1;
inline constexpr std::uint64_t
    kCiphertextCommitmentCorrectionFactor = 1;

inline Fq diagnostic_simple_ct_hash_initial_state(
    std::size_t ring_degree) {
    if (ring_degree == 0) {
        throw std::invalid_argument(
            "diagnostic ciphertext hash has zero ring degree");
    }
    const Fq alpha(kDiagnosticSimpleCtHashAlpha);
    Fq state(kDiagnosticSimpleCtHashInitialState);
    const std::array<Fq, kCiphertextCommitmentMetadataElements> metadata{
        Fq(static_cast<std::uint64_t>(ring_degree)),
        Fq(kCiphertextCommitmentComponents),
        Fq(kCiphertextCommitmentNttFlag),
        Fq(kCiphertextCommitmentCorrectionFactor)};
    for (const Fq &element : metadata) {
        state = alpha * state + element;
    }
    return state;
}

inline std::array<Fq, kPoseidonDigestElements>
diagnostic_simple_ct_hash_output_fields(const Fq &state) {
    std::array<Fq, kPoseidonDigestElements> result{};
    for (std::size_t element = 0; element < result.size(); ++element) {
        result[element] =
            state + Fq(kDiagnosticSimpleCtHashOutputDomains[element]);
    }
    return result;
}

/// Commitment to one canonical backend ciphertext encoding.
///
/// `HashCommitCT` is an algorithm-neutral protocol name.  The setup fixes the
/// concrete relation, and the same policy is authenticated by the host
/// commitment code and packing R1CS.
struct PackedMessageCommitment {
    PoseidonDigest digest{};

    bool operator==(const PackedMessageCommitment &) const = default;
};

/// Algorithm-neutral alias used by the coefficient-commitment compiler.
/// Protocol-facing GKR code uses `PackedMessageCommitment`.
using HashCommitCT = PackedMessageCommitment;

/// Public-or-committed fixed message carried by a Folded/Laned proof.
///
/// Public messages are exposed canonically so the verifier can derive their
/// exact bottom-q coordinate contribution. Private messages retain only the
/// setup-selected commitment authenticated by transcript packing.
class CommittedPackedMessage {
  public:
    CommittedPackedMessage() = default;

    static CommittedPackedMessage public_message(
        fhe::PublicPlaintext plaintext) {
        return CommittedPackedMessage(std::move(plaintext));
    }

    static CommittedPackedMessage encrypted_message(
        PackedMessageCommitment commitment) {
        return CommittedPackedMessage(std::move(commitment));
    }

    bool is_public() const {
        return std::holds_alternative<fhe::PublicPlaintext>(value_);
    }

    bool is_encrypted() const {
        return std::holds_alternative<PackedMessageCommitment>(value_);
    }

    const fhe::PublicPlaintext &plaintext() const {
        if (!is_public()) {
            throw std::logic_error(
                "CommittedPackedMessage::plaintext: message is encrypted");
        }
        return std::get<fhe::PublicPlaintext>(value_);
    }

    const PackedMessageCommitment &commitment() const {
        if (!is_encrypted()) {
            throw std::logic_error(
                "CommittedPackedMessage::commitment: message is public");
        }
        return std::get<PackedMessageCommitment>(value_);
    }

    bool operator==(const CommittedPackedMessage &) const = default;

  private:
    explicit CommittedPackedMessage(fhe::PublicPlaintext plaintext)
        : value_(std::move(plaintext)) {}
    explicit CommittedPackedMessage(PackedMessageCommitment commitment)
        : value_(std::move(commitment)) {}

    std::variant<PackedMessageCommitment, fhe::PublicPlaintext> value_;
};

/// Optional prover-side adapter used when a protocol commits to a public
/// canonicalization of the ciphertext being emitted (for example, the fixed
/// proof-of-packing alignment) rather than to its transient transport form.
/// An empty function retains the ordinary diagnostic/raw commitment path.
template <fhe::FheBackend Backend>
using CiphertextCommitmentFunction = std::function<HashCommitCT(
    const typename Backend::Ciphertext &)>;

/// Commitment adapter for one Folded/Laned fixed-message value. Complete
/// Laminate protocols supply the aligned coefficient commitment callback;
/// standalone GKR uses the canonical diagnostic commitment below.
template <fhe::FheBackend Backend>
using PackedMessageCommitmentFunction = std::function<HashCommitCT(
    const fhe::FheValue<Backend> &)>;

/// Canonical preimage for a normalized size-two ciphertext. Metadata is
/// `[N, components=2, NTT=1, correction-factor=1]`, followed by the exact
/// component-major one-prime NTT coordinates.
inline std::vector<Fq> ciphertext_commitment_preimage(
    std::size_t ring_degree,
    std::span<const std::uint64_t> component_major_coordinates) {
    if (ring_degree == 0 ||
        ring_degree > std::numeric_limits<std::size_t>::max() / 2U ||
        component_major_coordinates.size() != 2 * ring_degree) {
        throw std::invalid_argument(
            "ciphertext commitment has invalid normalized dimensions");
    }
    std::vector<Fq> result;
    result.reserve(kCiphertextCommitmentMetadataElements +
                   component_major_coordinates.size());
    result.emplace_back(static_cast<std::uint64_t>(ring_degree));
    result.emplace_back(kCiphertextCommitmentComponents);
    result.emplace_back(kCiphertextCommitmentNttFlag);
    result.emplace_back(kCiphertextCommitmentCorrectionFactor);
    for (const std::uint64_t coordinate : component_major_coordinates) {
        if (coordinate >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "ciphertext commitment coordinate is not canonical");
        }
        result.emplace_back(coordinate);
    }
    return result;
}

inline HashCommitCT hash_commit_normalized_ciphertext_coordinates(
    std::size_t ring_degree,
    std::span<const std::uint64_t> component_major_coordinates,
    CiphertextCommitmentPolicy policy =
        CiphertextCommitmentPolicy::poseidon_v2()) {
    policy.validate();
    const std::vector<Fq> preimage = ciphertext_commitment_preimage(
        ring_degree, component_major_coordinates);
    if (policy.relation == CiphertextCommitmentRelation::PoseidonV2) {
        return HashCommitCT{poseidon_hash_fields(
            preimage, PoseidonDomain::CiphertextCommitment,
            static_cast<std::uint64_t>(preimage.size()))};
    }

    Fq state = diagnostic_simple_ct_hash_initial_state(ring_degree);
    const Fq alpha(kDiagnosticSimpleCtHashAlpha);
    for (std::size_t index = kCiphertextCommitmentMetadataElements;
         index < preimage.size(); ++index) {
        state = alpha * state + preimage[index];
    }
    const auto output_fields =
        diagnostic_simple_ct_hash_output_fields(state);
    PoseidonDigest digest{};
    for (std::size_t element = 0;
         element < kPoseidonDigestElements; ++element) {
        const std::uint64_t word = output_fields[element].value();
        for (std::size_t byte = 0; byte < 8; ++byte) {
            digest[8 * element + byte] = static_cast<std::uint8_t>(
                (word >> (8U * byte)) & std::uint64_t{0xff});
        }
    }
    return HashCommitCT{digest};
}

/// Commitment to the formal normalized BGV value `(c0,c1)=(0,0)`.
/// Callers with several public-zero messages should cache the result at their
/// fixed ring degree instead of rebuilding and hashing the same preimage.
inline HashCommitCT hash_commit_normalized_zero_ciphertext_coordinates(
    std::size_t ring_degree,
    CiphertextCommitmentPolicy policy =
        CiphertextCommitmentPolicy::poseidon_v2()) {
    if (ring_degree == 0 ||
        ring_degree > std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::invalid_argument(
            "zero ciphertext commitment has invalid ring degree");
    }
    const std::vector<std::uint64_t> coordinates(2 * ring_degree, 0);
    return hash_commit_normalized_ciphertext_coordinates(
        ring_degree, coordinates, policy);
}

inline std::array<Fq, kPoseidonDigestElements>
hash_commitment_field_elements(const HashCommitCT &commitment) {
    return poseidon_digest_field_elements(commitment.digest);
}

namespace ciphertext_commitment_detail {

inline void append_u64(std::vector<std::uint8_t> &output,
                       std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

} // namespace ciphertext_commitment_detail

/// Hash the complete canonical ciphertext representation. Proof position is
/// bound separately by the Folded/Laned transcript observation labels.
template <fhe::FheBackend Backend>
HashCommitCT hash_commit_ciphertext(
    const typename Backend::Ciphertext &ciphertext) {
    static constexpr std::uint8_t kDomain[]{
        'L', 'a', 'm', 'i', 'n', 'a', 't', 'e', 'I', 'm', 'p', 'l', '/',
        'H', 'a', 's', 'h', 'C', 'o', 'm', 'm', 'i', 't', 'C', 'T', '/',
        'v', '1'};
    const std::vector<std::uint8_t> ciphertext_bytes =
        Backend::serialize(ciphertext);
    std::vector<std::uint8_t> encoding(std::begin(kDomain),
                                       std::end(kDomain));
    ciphertext_commitment_detail::append_u64(
        encoding, static_cast<std::uint64_t>(ciphertext_bytes.size()));
    encoding.insert(encoding.end(), ciphertext_bytes.begin(),
                    ciphertext_bytes.end());
    return HashCommitCT{poseidon_hash(
        encoding, PoseidonDomain::CiphertextCommitment)};
}

template <fhe::FheBackend Backend>
HashCommitCT commit_ciphertext(
    const typename Backend::Ciphertext &ciphertext,
    const CiphertextCommitmentFunction<Backend> &commitment_function = {}) {
    return commitment_function
               ? commitment_function(ciphertext)
               : hash_commit_ciphertext<Backend>(ciphertext);
}

template <fhe::FheBackend Backend>
HashCommitCT hash_commit_packed_message(
    const fhe::FheValue<Backend> &message) {
    if (message.is_encrypted()) {
        return hash_commit_ciphertext<Backend>(message.ciphertext());
    }

    static constexpr std::uint8_t kDomain[]{
        'L', 'a', 'm', 'i', 'n', 'a', 't', 'e', 'I', 'm', 'p', 'l', '/',
        'P', 'u', 'b', 'l', 'i', 'c', 'F', 'i', 'x', 'e', 'd', 'M', 's', 'g',
        '/', 'v', '1'};
    std::vector<std::uint8_t> encoding(std::begin(kDomain),
                                       std::end(kDomain));
    const fhe::PublicPlaintext &plaintext = message.plaintext();
    encoding.push_back(plaintext.is_scalar() ? 0U : 1U);
    if (plaintext.is_scalar()) {
        ciphertext_commitment_detail::append_u64(
            encoding, plaintext.scalar().value());
    } else {
        ciphertext_commitment_detail::append_u64(
            encoding, static_cast<std::uint64_t>(plaintext.slots().size()));
        for (const Fp &slot : plaintext.slots()) {
            ciphertext_commitment_detail::append_u64(encoding,
                                                     slot.value());
        }
    }
    return HashCommitCT{poseidon_hash(
        encoding, PoseidonDomain::CiphertextCommitment)};
}

template <fhe::FheBackend Backend>
CommittedPackedMessage commit_packed_message(
    const fhe::FheValue<Backend> &message,
    const PackedMessageCommitmentFunction<Backend> &commitment_function = {}) {
    std::optional<PackedMessageCommitment> commitment;
    if (commitment_function) {
        commitment = commitment_function(message);
    }
    if (message.is_public()) {
        return CommittedPackedMessage::public_message(message.plaintext());
    }
    return CommittedPackedMessage::encrypted_message(
        commitment ? std::move(*commitment)
                   : hash_commit_packed_message<Backend>(message));
}

// Sparse public messages store the slot count and the number of nonzero
// entries, followed by increasing (slot index, field value) pairs.
inline constexpr std::size_t kCommittedPublicSparseHeaderBytes = 18;
inline constexpr std::size_t kCommittedPublicSparseEntryBytes = 16;

inline std::size_t committed_public_nonzero_count(
    std::span<const Fp> slots) {
    return static_cast<std::size_t>(std::count_if(
        slots.begin(), slots.end(), [](const Fp &value) {
            return value != Fp::zero();
        }));
}

inline constexpr bool committed_public_uses_sparse(
    std::size_t slot_count, std::size_t nonzero_count) {
    // 18 + 16*z < 10 + 8*N, without overflowing either encoded size.
    // A tie uses the dense form, so each public value has one encoding.
    return nonzero_count < slot_count / 2U;
}

inline void append_committed_packed_message(
    std::vector<std::uint8_t> &output,
    const CommittedPackedMessage &message) {
    output.push_back(message.is_public() ? 0U : 1U);
    if (message.is_encrypted()) {
        output.insert(output.end(), message.commitment().digest.begin(),
                      message.commitment().digest.end());
        return;
    }
    const fhe::PublicPlaintext &plaintext = message.plaintext();
    if (plaintext.is_scalar()) {
        output.push_back(0U);
        ciphertext_commitment_detail::append_u64(
            output, plaintext.scalar().value());
        return;
    }
    const auto &slots = plaintext.slots();
    const std::size_t nonzero = committed_public_nonzero_count(slots);
    const bool sparse = committed_public_uses_sparse(slots.size(), nonzero);
    output.push_back(sparse ? 2U : 1U);
    ciphertext_commitment_detail::append_u64(
        output, static_cast<std::uint64_t>(slots.size()));
    if (sparse) {
        ciphertext_commitment_detail::append_u64(
            output, static_cast<std::uint64_t>(nonzero));
        for (std::size_t index = 0; index < slots.size(); ++index) {
            if (slots[index] == Fp::zero()) {
                continue;
            }
            ciphertext_commitment_detail::append_u64(
                output, static_cast<std::uint64_t>(index));
            ciphertext_commitment_detail::append_u64(
                output, slots[index].value());
        }
    } else {
        for (const Fp &slot : slots) {
            ciphertext_commitment_detail::append_u64(output, slot.value());
        }
    }
}

inline void append_hash_commitment(std::vector<std::uint8_t> &output,
                                   const HashCommitCT &commitment) {
    output.insert(output.end(), commitment.digest.begin(),
                  commitment.digest.end());
}

} // namespace laminate::gkr

#endif // LAMINATE_GKR_CIPHERTEXT_COMMITMENT_HPP
