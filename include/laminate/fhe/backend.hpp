#ifndef LAMINATE_FHE_BACKEND_HPP
#define LAMINATE_FHE_BACKEND_HPP

/// @file backend.hpp
/// @brief Compile-time interface shared by Mock and real BGV backends.

#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/fhe/layout/fixed_message.hpp"
#include "laminate/params.hpp"

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::fhe {

using PlainExtension = std::array<SlotVector, kExtensionDegree>;
/// One extension-field plaintext replicated across every SIMD slot. Unlike
/// `PlainExtension`, this representation owns only kExtensionDegree values.
using PlainExtensionScalar = std::array<Fp, kExtensionDegree>;

/// One encrypted extension-field value in coefficient representation.
///
/// An absent coordinate is a publicly known algebraic zero. It is deliberately
/// not an encryption of zero: extension arithmetic propagates the symbolic
/// value without invoking the FHE backend. A present coordinate may still
/// encrypt the plaintext value zero; its presence means the zero is not
/// public structural information and must remain hidden as a ciphertext.
template <typename Ciphertext>
using ExtensionCiphertext =
    std::array<std::optional<Ciphertext>, kExtensionDegree>;

struct PreparedBasisStorageStats {
    std::size_t level_representations = 0;
    std::size_t ntt_coefficient_bytes = 0;
    std::size_t host_basis_bytes = 0;

    bool operator==(const PreparedBasisStorageStats &) const = default;
};

template <typename Backend>
concept FheBackend = requires(
    const typename Backend::EvalContext &eval,
    const typename Backend::ClientContext &client,
    const typename Backend::Ciphertext &ciphertext,
    typename Backend::Ciphertext &mutable_ciphertext,
    const typename Backend::ExtCiphertext &extension,
    typename Backend::ExtCiphertext &mutable_extension,
    const SlotVector &slots, const Fp &scalar,
    const PlainExtension &plain_extension,
    const PlainExtensionScalar &plain_extension_scalar) {
    typename Backend::Ciphertext;
    typename Backend::ExtCiphertext;
    typename Backend::PreparedSlotBasis;
    typename Backend::PreparedLevelSlotBasis;
    typename Backend::PreparedExtensionSlotBasis;
    typename Backend::EvalContext;
    typename Backend::ClientContext;

    { Backend::encrypt(client, slots) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::decrypt(client, ciphertext) } -> std::same_as<SlotVector>;

    { Backend::negate(eval, ciphertext) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::add(eval, ciphertext, ciphertext) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::sub(eval, ciphertext, ciphertext) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::mul_no_relin(eval, ciphertext, ciphertext) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::relinearize(eval, mutable_ciphertext) };
    { Backend::mul(eval, ciphertext, ciphertext) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::add_plain(eval, ciphertext, slots) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::add_plain_scalar(eval, ciphertext, scalar) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::mul_plain(eval, ciphertext, slots) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::mul_plain_scalar(eval, ciphertext, scalar) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::prepare_slot_basis(eval, slots) } ->
        std::same_as<typename Backend::PreparedSlotBasis>;
    { Backend::mul_plain_prepared(
          eval, ciphertext,
          std::declval<const typename Backend::PreparedSlotBasis &>()) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::prepare_level_slot_basis(eval, ciphertext, slots) } ->
        std::same_as<typename Backend::PreparedLevelSlotBasis>;
    { Backend::mul_plain_level_prepared(
          eval, ciphertext,
          std::declval<const typename Backend::PreparedLevelSlotBasis &>()) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::prepared_level_slot_basis_storage(
          std::declval<const typename Backend::PreparedLevelSlotBasis &>()) } ->
        std::same_as<PreparedBasisStorageStats>;
    { Backend::preprocess_fixed_message_cells(eval) };
    { Backend::mul_plain_fixed_message_cell(
          eval, ciphertext, std::size_t{}) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::prepare_extension_slot_basis(
          eval, ciphertext, plain_extension) } ->
        std::same_as<typename Backend::PreparedExtensionSlotBasis>;
    { Backend::ext_mul_plain_prepared(
          eval, extension,
          std::declval<const
                       typename Backend::PreparedExtensionSlotBasis &>()) } ->
        std::same_as<typename Backend::ExtCiphertext>;
    { Backend::promote_plain_prepared(
          eval, ciphertext,
          std::declval<const
                       typename Backend::PreparedExtensionSlotBasis &>()) } ->
        std::same_as<typename Backend::ExtCiphertext>;
    { Backend::prepared_extension_slot_basis_storage(
          std::declval<const
                       typename Backend::PreparedExtensionSlotBasis &>()) } ->
        std::same_as<PreparedBasisStorageStats>;
    { Backend::rotate(eval, ciphertext, std::size_t{}) } ->
        std::same_as<typename Backend::Ciphertext>;
    { Backend::fold(eval, ciphertext) } ->
        std::same_as<typename Backend::Ciphertext>;

    { Backend::ext_add(eval, extension, extension) } ->
        std::same_as<typename Backend::ExtCiphertext>;
    { Backend::ext_sub(eval, extension, extension) } ->
        std::same_as<typename Backend::ExtCiphertext>;
    { Backend::ext_mul_no_relin(eval, extension, extension) } ->
        std::same_as<typename Backend::ExtCiphertext>;
    { Backend::ext_relinearize(eval, mutable_extension) };
    { Backend::ext_mul(eval, extension, extension) } ->
        std::same_as<typename Backend::ExtCiphertext>;
    { Backend::ext_mul_plain(eval, extension, plain_extension) } ->
        std::same_as<typename Backend::ExtCiphertext>;
    { Backend::ext_mul_plain_scalar(eval, extension,
                                    plain_extension_scalar) } ->
        std::same_as<typename Backend::ExtCiphertext>;
    { Backend::mod_switch_to_next(eval, mutable_ciphertext) };
    { Backend::mod_switch_to_lowest(eval, mutable_ciphertext) };
    { Backend::remaining_mult_depth(eval, ciphertext) } ->
        std::convertible_to<std::size_t>;
    { Backend::rns_limb_count(eval, ciphertext) } ->
        std::convertible_to<std::size_t>;
    { Backend::coeff_modulus_bits(eval, ciphertext) } ->
        std::convertible_to<std::size_t>;
    { Backend::estimated_noise_bits(eval, ciphertext) } ->
        std::convertible_to<int>;

    { Backend::slot_count(eval) } -> std::convertible_to<std::size_t>;
    { Backend::slot_count(client) } -> std::convertible_to<std::size_t>;
    { Backend::serialize(ciphertext) } ->
        std::same_as<std::vector<std::uint8_t>>;
};

/// Role-separated public capability used by packed-proof clients.
///
/// A conforming backend can project the immutable parameter/encoding state
/// needed by verification without exposing its evaluation context.  The
/// packing layer refines this small backend-level concept with the concrete
/// public coefficient operations it needs.
template <typename Backend>
concept PublicVerifierFheBackend =
    FheBackend<Backend> &&
    requires(const typename Backend::EvalContext &eval,
             const typename Backend::ClientContext &client,
             const typename Backend::PublicVerifierContext &verifier) {
        typename Backend::PublicVerifierContext;
        {
            Backend::make_public_verifier_context(eval)
        } -> std::same_as<typename Backend::PublicVerifierContext>;
        {
            Backend::make_public_verifier_context(client)
        } -> std::same_as<typename Backend::PublicVerifierContext>;
        { Backend::slot_count(verifier) } ->
            std::convertible_to<std::size_t>;
    };

/// Add `term` to an accumulator without requiring generic protocol code to
/// allocate a replacement ciphertext. Backends may provide an optimized
/// in-place implementation; the returned-value interface remains the
/// portable fallback.
template <FheBackend Backend>
void add_assign(const typename Backend::EvalContext &eval,
                typename Backend::Ciphertext &accumulator,
                const typename Backend::Ciphertext &term) {
    if constexpr (requires {
                      {
                          Backend::add_assign(eval, accumulator, term)
                      } -> std::same_as<void>;
                  }) {
        Backend::add_assign(eval, accumulator, term);
    } else {
        accumulator = Backend::add(eval, accumulator, term);
    }
}

/// Add into an owned ciphertext while allowing a backend to report that the
/// result no longer depends on the secret key. Most backends never expose a
/// transparent representation and use the ordinary in-place path. A backend
/// that can recognize one returns its public SIMD plaintext so typed callers
/// can stop carrying it as a ciphertext.
template <FheBackend Backend>
std::optional<SlotVector> add_assign_or_public(
    const typename Backend::EvalContext &eval,
    typename Backend::Ciphertext &accumulator,
    const typename Backend::Ciphertext &term) {
    if constexpr (requires {
                      {
                          Backend::add_assign_or_public(
                              eval, accumulator, term)
                      } -> std::same_as<std::optional<SlotVector>>;
                  }) {
        return Backend::add_assign_or_public(eval, accumulator, term);
    }
    add_assign<Backend>(eval, accumulator, term);
    return std::nullopt;
}

/// Subtract from an owned ciphertext while allowing a backend to report that
/// correlated operands cancelled their secret-key-dependent components. The
/// portable fallback retains the ordinary ciphertext-only subtraction.
template <FheBackend Backend>
std::optional<SlotVector> sub_assign_or_public(
    const typename Backend::EvalContext &eval,
    typename Backend::Ciphertext &accumulator,
    const typename Backend::Ciphertext &term) {
    if constexpr (requires {
                      {
                          Backend::sub_assign_or_public(
                              eval, accumulator, term)
                      } -> std::same_as<std::optional<SlotVector>>;
                  }) {
        return Backend::sub_assign_or_public(eval, accumulator, term);
    }
    accumulator = Backend::sub(eval, accumulator, term);
    return std::nullopt;
}

/// Extension-field counterpart of `add_assign`. The fallback deliberately
/// calls the backend's logical extension addition so operation accounting and
/// bound-only backends retain their existing semantics.
template <FheBackend Backend>
void ext_add_assign(const typename Backend::EvalContext &eval,
                    typename Backend::ExtCiphertext &accumulator,
                    const typename Backend::ExtCiphertext &term) {
    if constexpr (requires {
                      {
                          Backend::ext_add_assign(eval, accumulator, term)
                      } -> std::same_as<void>;
                  }) {
        Backend::ext_add_assign(eval, accumulator, term);
    } else {
        accumulator = Backend::ext_add(eval, accumulator, term);
    }
}

/// Record one logical extension addition without performing raw extension
/// arithmetic. Typed extension values use this boundary before operating on
/// their independently public-or-encrypted coordinates. Backends that do not
/// expose operation telemetry need no implementation.
template <FheBackend Backend>
void record_logical_extension_add(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &encrypted_anchor) {
    if constexpr (requires {
                      {
                          Backend::record_logical_extension_add(
                              eval, encrypted_anchor)
                      } -> std::same_as<void>;
                  }) {
        Backend::record_logical_extension_add(eval, encrypted_anchor);
    }
}

/// Subtraction counterpart of `record_logical_extension_add`.
template <FheBackend Backend>
void record_logical_extension_sub(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &encrypted_anchor) {
    if constexpr (requires {
                      {
                          Backend::record_logical_extension_sub(
                              eval, encrypted_anchor)
                      } -> std::same_as<void>;
                  }) {
        Backend::record_logical_extension_sub(eval, encrypted_anchor);
    }
}

/// Multiplication-by-public counterpart of the typed logical-operation hooks.
/// Public-aware extension convolution sometimes performs the coefficient
/// additions itself so that a transparent result can remain a public value;
/// this hook preserves the backend's one-operation telemetry in that path.
template <FheBackend Backend>
void record_logical_extension_mul_plain(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &encrypted_anchor) {
    if constexpr (requires {
                      {
                          Backend::record_logical_extension_mul_plain(
                              eval, encrypted_anchor)
                      } -> std::same_as<void>;
                  }) {
        Backend::record_logical_extension_mul_plain(eval, encrypted_anchor);
    }
}

/// Internal prepared promotion used to implement one typed extension
/// multiplication. Backends may suppress only the top-level promotion API
/// counter here; underlying ciphertext/plaintext work remains observable.
template <FheBackend Backend>
typename Backend::ExtCiphertext promote_plain_prepared_internal(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    const typename Backend::PreparedExtensionSlotBasis &basis) {
    if constexpr (requires {
                      {
                          Backend::promote_plain_prepared_untracked(
                              eval, ciphertext, basis)
                      } -> std::same_as<typename Backend::ExtCiphertext>;
                  }) {
        return Backend::promote_plain_prepared_untracked(
            eval, ciphertext, basis);
    }
    return Backend::promote_plain_prepared(eval, ciphertext, basis);
}

template <FheBackend Backend> struct PreparedFpSlotBasis {
    typename Backend::PreparedLevelSlotBasis backend_basis;
    std::size_t slot_count = 0;
    PreparedBasisStorageStats storage;
};

template <FheBackend Backend>
PreparedFpSlotBasis<Backend> prepare_fp_slot_basis(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &level_reference,
    std::span<const Fp> basis) {
    if (basis.size() != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "prepare_fp_slot_basis: basis must fill all slots");
    }
    auto backend_basis = Backend::prepare_level_slot_basis(
        eval, level_reference, SlotVector(basis.begin(), basis.end()));
    const PreparedBasisStorageStats storage =
        Backend::prepared_level_slot_basis_storage(backend_basis);
    return PreparedFpSlotBasis<Backend>{std::move(backend_basis),
                                        basis.size(), storage};
}

template <FheBackend Backend>
typename Backend::Ciphertext mul_plain_prepared(
    const typename Backend::EvalContext &eval,
    const typename Backend::Ciphertext &ciphertext,
    const PreparedFpSlotBasis<Backend> &basis) {
    if (basis.slot_count != Backend::slot_count(eval)) {
        throw std::invalid_argument(
            "mul_plain_prepared: basis has the wrong slot count");
    }
    return Backend::mul_plain_level_prepared(
        eval, ciphertext, basis.backend_basis);
}

/// Whether this backend is executing a bound-only topology envelope.
///
/// Ordinary FHE backends return false without adding anything to their public
/// interface. The offline noise-envelope backend opts in, and generic prover
/// helpers then retain algebraically zero challenge terms instead of taking
/// performance shortcuts. This is certificate work, never an online mode.
template <FheBackend Backend>
bool forces_challenge_independent_topology(
    const typename Backend::EvalContext &eval) {
    if constexpr (requires {
                      {
                          Backend::forces_challenge_independent_topology(eval)
                      } -> std::convertible_to<bool>;
                  }) {
        return Backend::forces_challenge_independent_topology(eval);
    }
    return false;
}

template <FheBackend Backend>
typename Backend::ExtCiphertext
ext_fold(const typename Backend::EvalContext &eval,
         const typename Backend::ExtCiphertext &extension) {
    typename Backend::ExtCiphertext result{};
    for (std::size_t limb = 0; limb < kExtensionDegree; ++limb) {
        if (extension[limb]) {
            result[limb] = Backend::fold(eval, *extension[limb]);
        }
    }
    return result;
}

/// Drop a ciphertext to one exact RNS limb count.
///
/// This is the mechanism for a setup-selected proof ingress. The caller has
/// already selected and admitted the target, so this helper does not infer a
/// level from a backend noise heuristic. A target above the source level is an
/// error because modulus switching cannot raise a ciphertext back up the
/// chain.
template <FheBackend Backend>
void mod_switch_to_rns_limb_count(
    const typename Backend::EvalContext &eval,
    typename Backend::Ciphertext &ciphertext,
    std::size_t target_rns_limbs) {
    const std::size_t source_rns_limbs =
        Backend::rns_limb_count(eval, ciphertext);
    if (target_rns_limbs == 0 || target_rns_limbs > source_rns_limbs) {
        throw std::invalid_argument(
            "mod_switch_to_rns_limb_count: target is outside the source "
            "chain");
    }
    while (Backend::rns_limb_count(eval, ciphertext) > target_rns_limbs) {
        Backend::mod_switch_to_next(eval, ciphertext);
    }
    if (Backend::rns_limb_count(eval, ciphertext) != target_rns_limbs) {
        throw std::logic_error(
            "mod_switch_to_rns_limb_count: backend missed the exact "
            "target");
    }
}

template <FheBackend Backend>
void mod_switch_to_rns_limb_count(
    const typename Backend::EvalContext &eval,
    std::vector<typename Backend::Ciphertext> &ciphertexts,
    std::size_t target_rns_limbs) {
    for (typename Backend::Ciphertext &ciphertext : ciphertexts) {
        mod_switch_to_rns_limb_count<Backend>(
            eval, ciphertext, target_rns_limbs);
    }
}

/// Greedily remove transport-only RNS limbs while preserving a positive
/// public noise estimate. Unlike `mod_switch_to_lowest`, this deliberately
/// permits a client-bound ciphertext to retain multiple limbs when the final
/// modulus would be too small for its computation history.
template <FheBackend Backend>
void compact_for_transport(const typename Backend::EvalContext &eval,
                           typename Backend::Ciphertext &ciphertext,
                           std::size_t reserved_mult_depth = 0) {
    if (Backend::remaining_mult_depth(eval, ciphertext) <
        reserved_mult_depth) {
        throw std::invalid_argument(
            "compact_for_transport: requested reserve is unavailable");
    }
    while (Backend::rns_limb_count(eval, ciphertext) > 1) {
        const std::size_t limbs =
            Backend::rns_limb_count(eval, ciphertext);
        const std::size_t modulus_bits =
            Backend::coeff_modulus_bits(eval, ciphertext);
        const std::size_t removable_bits =
            (modulus_bits + limbs - 1) / limbs;
        const int estimate = Backend::estimated_noise_bits(eval, ciphertext);
        if (estimate <= 0 ||
            static_cast<std::size_t>(estimate) <= removable_bits) {
            break;
        }
        if (reserved_mult_depth != 0 &&
            Backend::remaining_mult_depth(eval, ciphertext) <=
                reserved_mult_depth) {
            break;
        }
        typename Backend::Ciphertext candidate = ciphertext;
        Backend::mod_switch_to_next(eval, candidate);
        if (Backend::estimated_noise_bits(eval, candidate) <= 0 ||
            Backend::remaining_mult_depth(eval, candidate) <
                reserved_mult_depth) {
            break;
        }
        ciphertext = std::move(candidate);
    }
}

} // namespace laminate::fhe

#endif // LAMINATE_FHE_BACKEND_HPP
