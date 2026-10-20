/// @file envelope_backend.cpp
/// @brief Bound-only implementation of the dense Fiat--Shamir topology.

#include "laminate/fhe/noise/envelope_backend.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace laminate::fhe {
namespace {

using Backend = NoiseEnvelopeBackend;
using Ciphertext = Backend::Ciphertext;
using EvalContext = Backend::EvalContext;
using OptionalCiphertext = std::optional<Ciphertext>;

std::span<const std::uint64_t> active_moduli(
    const NoiseEnvelopeParameters &parameters, std::size_t limbs) {
    if (limbs == 0 || limbs > parameters.data_moduli.size()) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend: invalid RNS limb count");
    }
    return std::span<const std::uint64_t>(parameters.data_moduli)
        .first(limbs);
}

std::uint64_t next_identity(
    const std::shared_ptr<Backend::IdentityState> &state) {
    if (!state || state->next == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(
            "NoiseEnvelopeBackend: ciphertext identity exhausted");
    }
    return state->next++;
}

template <typename Context>
Ciphertext make_ciphertext(const Context &context,
                           DeterministicNoiseBound bound,
                           std::size_t limbs,
                           std::size_t components = 2) {
    return Ciphertext{std::move(bound), limbs, components,
                      next_identity(context.identities),
                      context.identities};
}

template <typename Context>
void validate_ciphertext(const Context &context,
                         const Ciphertext &ciphertext,
                         const char *operation) {
    if (ciphertext.rns_limbs == 0 ||
        ciphertext.rns_limbs > context.parameters.data_moduli.size() ||
        ciphertext.component_count < 2 || ciphertext.identity == 0 ||
        !context.identities || !ciphertext.context_token ||
        context.identities.get() != ciphertext.context_token.get()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": malformed bound ciphertext");
    }
}

std::optional<std::size_t> validate_extension(
    const EvalContext &context, const Backend::ExtCiphertext &ciphertext,
    const char *operation) {
    std::optional<std::size_t> expected_limbs;
    for (const auto &coefficient : ciphertext) {
        if (!coefficient) {
            continue;
        }
        validate_ciphertext(context, *coefficient, operation);
        if (expected_limbs && coefficient->rns_limbs != *expected_limbs) {
            throw std::invalid_argument(
                std::string(operation) +
                ": extension coefficients have different RNS levels");
        }
        expected_limbs = coefficient->rns_limbs;
    }
    return expected_limbs;
}

void validate_extension_pair(
    const EvalContext &context, const Backend::ExtCiphertext &left,
    const Backend::ExtCiphertext &right, const char *operation) {
    const std::optional<std::size_t> left_limbs =
        validate_extension(context, left, operation);
    const std::optional<std::size_t> right_limbs =
        validate_extension(context, right, operation);
    if (left_limbs && right_limbs && left_limbs != right_limbs) {
        throw std::invalid_argument(
            std::string(operation) +
            ": extension operands have different RNS levels");
    }
}

void switch_to_limbs(const EvalContext &context, Ciphertext &ciphertext,
                     std::size_t limbs) {
    while (ciphertext.rns_limbs > limbs) {
        Backend::mod_switch_to_next(context, ciphertext);
    }
}

std::pair<Ciphertext, Ciphertext> align(
    const EvalContext &context, const Ciphertext &left,
    const Ciphertext &right) {
    validate_ciphertext(context, left,
                        "NoiseEnvelopeBackend::align");
    validate_ciphertext(context, right,
                        "NoiseEnvelopeBackend::align");
    Ciphertext aligned_left = left;
    Ciphertext aligned_right = right;
    const std::size_t target =
        std::min(aligned_left.rns_limbs, aligned_right.rns_limbs);
    switch_to_limbs(context, aligned_left, target);
    switch_to_limbs(context, aligned_right, target);
    return {std::move(aligned_left), std::move(aligned_right)};
}

bool is_scalar_plaintext(std::span<const Fp> plaintext,
                         std::size_t slot_count) {
    const Fp first = plaintext.empty() ? Fp::zero() : plaintext.front();
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        const Fp value =
            slot < plaintext.size() ? plaintext[slot] : Fp::zero();
        if (!(value == first)) {
            return false;
        }
    }
    return true;
}

std::uint64_t plaintext_l1_bound(const EvalContext &context,
                                 std::span<const Fp> plaintext) {
    const bool scalar =
        is_scalar_plaintext(plaintext, Backend::slot_count(context));
    const std::uint64_t coefficient_count =
        scalar ? 1 : static_cast<std::uint64_t>(Backend::slot_count(context));
    const std::uint64_t radius = context.parameters.policy.plaintext_radius();
    if (coefficient_count >
        std::numeric_limits<std::uint64_t>::max() / radius) {
        throw std::overflow_error(
            "NoiseEnvelopeBackend: plaintext l1 bound overflows");
    }
    return coefficient_count * radius;
}

void accumulate(const EvalContext &context,
                OptionalCiphertext &destination, Ciphertext term) {
    destination = destination
                      ? Backend::add(context, *destination, term)
                      : std::move(term);
}

template <std::size_t Size>
void reduce_extension_polynomial(
    const EvalContext &context,
    std::array<OptionalCiphertext, Size> &coefficients) {
    static_assert(Size >= 2 * kExtensionDegree - 1);
    for (std::size_t degree = Size; degree-- > kExtensionDegree;) {
        if (!coefficients[degree]) {
            continue;
        }
        const Ciphertext negative =
            Backend::negate(context, *coefficients[degree]);
        for (std::size_t coefficient = 0;
             coefficient < kExtensionDegree; ++coefficient) {
            const std::uint64_t modulus_coefficient =
                kExtensionModulusPoly[coefficient];
            if (modulus_coefficient == 0) {
                continue;
            }
            Ciphertext term =
                modulus_coefficient == 1
                    ? negative
                    : Backend::mul_plain(
                          context, negative,
                          SlotVector(Backend::slot_count(context),
                                     Fp(modulus_coefficient)));
            accumulate(context,
                       coefficients[degree - kExtensionDegree +
                                    coefficient],
                       std::move(term));
        }
    }
}

void append_u64(std::vector<std::uint8_t> &output,
                std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

} // namespace

void NoiseEnvelopeParameters::validate() const {
    policy.validate();
    if (policy.plaintext_modulus != kBaseFieldOrder || data_moduli.empty() ||
        special_modulus < 3 || special_modulus % 2 == 0) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend: invalid public parameters");
    }
    for (const std::uint64_t modulus : data_moduli) {
        if (modulus < 3 || modulus % 2 == 0) {
            throw std::invalid_argument(
                "NoiseEnvelopeBackend: data moduli must be odd");
        }
    }
}

Backend::Contexts Backend::create(NoiseEnvelopeParameters parameters) {
    parameters.validate();
    auto identities = std::make_shared<IdentityState>();
    return Contexts{EvalContext{parameters, identities},
                    ClientContext{std::move(parameters),
                                  std::move(identities)}};
}

Ciphertext Backend::encrypt(const ClientContext &context,
                            const SlotVector &slots) {
    if (slots.size() > slot_count(context)) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::encrypt: plaintext exceeds slot count");
    }
    return make_ciphertext(
        context,
        bound_fresh_asymmetric_encryption(
            context.parameters.policy,
            context.parameters.policy.plaintext_radius(),
            context.parameters.data_moduli),
        context.parameters.data_moduli.size());
}

SlotVector Backend::decrypt(const ClientContext &context,
                            const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::decrypt");
    return SlotVector(slot_count(context), Fp::zero());
}

Ciphertext Backend::negate(const EvalContext &context,
                           const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::negate");
    return make_ciphertext(context,
                           bound_negation(ciphertext.deterministic_noise_bound),
                           ciphertext.rns_limbs,
                           ciphertext.component_count);
}

Ciphertext Backend::add(const EvalContext &context,
                        const Ciphertext &left,
                        const Ciphertext &right) {
    auto [a, b] = align(context, left, right);
    return make_ciphertext(
        context,
        bound_addition(a.deterministic_noise_bound,
                       b.deterministic_noise_bound,
                       active_moduli(context.parameters, a.rns_limbs)),
        a.rns_limbs, std::max(a.component_count, b.component_count));
}

bool Backend::same_ciphertext(const EvalContext &context,
                              const Ciphertext &left,
                              const Ciphertext &right) {
    validate_ciphertext(context, left,
                        "NoiseEnvelopeBackend::same_ciphertext");
    validate_ciphertext(context, right,
                        "NoiseEnvelopeBackend::same_ciphertext");
    return left.identity == right.identity;
}

Ciphertext Backend::sub(const EvalContext &context,
                        const Ciphertext &left,
                        const Ciphertext &right) {
    if (same_ciphertext(context, left, right)) {
        throw std::logic_error(
            "NoiseEnvelopeBackend::sub: exact cancellation is a public "
            "FheValue zero, not a ciphertext");
    }
    auto [a, b] = align(context, left, right);
    return make_ciphertext(
        context,
        bound_addition(a.deterministic_noise_bound,
                       b.deterministic_noise_bound,
                       active_moduli(context.parameters, a.rns_limbs),
                       DeterministicNoiseOperation::Subtraction),
        a.rns_limbs, std::max(a.component_count, b.component_count));
}

Ciphertext Backend::mul_no_relin(const EvalContext &context,
                                 const Ciphertext &left,
                                 const Ciphertext &right) {
    if (left.component_count != 2 || right.component_count != 2) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::mul_no_relin: inputs must be size two");
    }
    auto [a, b] = align(context, left, right);
    return make_ciphertext(
        context,
        bound_ciphertext_multiplication(
            context.parameters.policy, a.deterministic_noise_bound,
            b.deterministic_noise_bound,
            active_moduli(context.parameters, a.rns_limbs)),
        a.rns_limbs, 3);
}

void Backend::relinearize(const EvalContext &context,
                          Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::relinearize");
    if (ciphertext.component_count <= 2) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::relinearize: already size two");
    }
    ciphertext.deterministic_noise_bound = bound_key_switch(
        context.parameters.policy, ciphertext.deterministic_noise_bound,
        active_moduli(context.parameters, ciphertext.rns_limbs),
        context.parameters.special_modulus,
        DeterministicNoiseOperation::Relinearization);
    ciphertext.component_count = 2;
    ciphertext.identity = next_identity(context.identities);
}

Ciphertext Backend::mul(const EvalContext &context,
                        const Ciphertext &left,
                        const Ciphertext &right) {
    Ciphertext result = mul_no_relin(context, left, right);
    relinearize(context, result);
    return result;
}

Ciphertext Backend::add_plain(const EvalContext &context,
                              const Ciphertext &ciphertext,
                              const SlotVector &plaintext) {
    if (plaintext.size() > slot_count(context)) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::add_plain: plaintext exceeds slots");
    }
    return make_ciphertext(
        context,
        bound_plaintext_addition(
            ciphertext.deterministic_noise_bound,
            context.parameters.policy.plaintext_radius(),
            active_moduli(context.parameters, ciphertext.rns_limbs)),
        ciphertext.rns_limbs, ciphertext.component_count);
}

Ciphertext Backend::add_plain_scalar(const EvalContext &context,
                                     const Ciphertext &ciphertext,
                                     const Fp &plaintext) {
    (void)plaintext;
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::add_plain_scalar");
    return make_ciphertext(
        context,
        bound_plaintext_addition(
            ciphertext.deterministic_noise_bound,
            context.parameters.policy.plaintext_radius(),
            active_moduli(context.parameters, ciphertext.rns_limbs)),
        ciphertext.rns_limbs, ciphertext.component_count);
}

Ciphertext Backend::mul_plain(const EvalContext &context,
                              const Ciphertext &ciphertext,
                              const SlotVector &plaintext) {
    if (plaintext.size() > slot_count(context)) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::mul_plain: plaintext exceeds slots");
    }
    return make_ciphertext(
        context,
        bound_plaintext_multiplication(
            ciphertext.deterministic_noise_bound,
            plaintext_l1_bound(context, plaintext),
            active_moduli(context.parameters, ciphertext.rns_limbs)),
        ciphertext.rns_limbs, ciphertext.component_count);
}

Ciphertext Backend::mul_plain_scalar(const EvalContext &context,
                                     const Ciphertext &ciphertext,
                                     const Fp &plaintext) {
    (void)plaintext;
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::mul_plain_scalar");
    return make_ciphertext(
        context,
        bound_plaintext_multiplication(
            ciphertext.deterministic_noise_bound,
            context.parameters.policy.plaintext_radius(),
            active_moduli(context.parameters, ciphertext.rns_limbs)),
        ciphertext.rns_limbs, ciphertext.component_count);
}

Backend::PreparedSlotBasis Backend::prepare_slot_basis(
    const EvalContext &context, const SlotVector &basis) {
    if (basis.size() != slot_count(context)) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::prepare_slot_basis: basis must fill all "
            "slots");
    }
    return PreparedSlotBasis{basis};
}

Ciphertext Backend::mul_plain_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedSlotBasis &basis) {
    return mul_plain(context, ciphertext, basis.plaintext);
}

Backend::PreparedLevelSlotBasis Backend::prepare_level_slot_basis(
    const EvalContext &context, const Ciphertext &level_reference,
    const SlotVector &basis) {
    validate_ciphertext(context, level_reference,
                        "NoiseEnvelopeBackend::prepare_level_slot_basis");
    if (basis.size() != slot_count(context)) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::prepare_level_slot_basis: basis must "
            "fill all slots");
    }
    return PreparedLevelSlotBasis{basis, level_reference.rns_limbs};
}

Ciphertext Backend::mul_plain_level_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedLevelSlotBasis &basis) {
    if (ciphertext.rns_limbs != basis.rns_limbs) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::mul_plain_level_prepared: wrong level");
    }
    return mul_plain(context, ciphertext, basis.plaintext);
}

PreparedBasisStorageStats Backend::prepared_level_slot_basis_storage(
    const PreparedLevelSlotBasis &basis) {
    return PreparedBasisStorageStats{
        1,
        basis.plaintext.size() * basis.rns_limbs * sizeof(std::uint64_t),
        basis.plaintext.size() * sizeof(Fp)};
}

void Backend::preprocess_fixed_message_cells(
    const EvalContext &context) {
    if (slot_count(context) < kFixedMessageCellCount) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::preprocess_fixed_message_cells: too "
            "few slots");
    }
}

Ciphertext Backend::mul_plain_fixed_message_cell(
    const EvalContext &context, const Ciphertext &ciphertext,
    std::size_t cell) {
    if (cell >= kFixedMessageCellCount) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::mul_plain_fixed_message_cell: cell is "
            "out of range");
    }
    // A one-cell mask is non-scalar. The bound backend deliberately charges
    // every non-scalar plaintext at the same challenge-independent envelope,
    // so one O(1)-sized host value is sufficient to select that topology.
    return mul_plain(context, ciphertext, SlotVector{Fp::one()});
}

Backend::PreparedExtensionSlotBasis
Backend::prepare_extension_slot_basis(
    const EvalContext &context, const Ciphertext &level_reference,
    const PlainExtension &basis) {
    validate_ciphertext(context, level_reference,
                        "NoiseEnvelopeBackend::prepare_extension_slot_basis");
    for (const SlotVector &coefficient : basis) {
        if (coefficient.size() != slot_count(context)) {
            throw std::invalid_argument(
                "NoiseEnvelopeBackend::prepare_extension_slot_basis: "
                "every coefficient must fill all slots");
        }
    }
    return PreparedExtensionSlotBasis{basis,
                                      level_reference.rns_limbs};
}

Ciphertext Backend::rotate(const EvalContext &context,
                           const Ciphertext &ciphertext,
                           std::size_t steps) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::rotate");
    Ciphertext result = ciphertext;
    const std::size_t width = slot_count(context);
    const std::size_t reduced = steps % width;
    const std::size_t half = width / 2;
    const auto one_rotation = [&] {
        result.deterministic_noise_bound = bound_key_switch(
            context.parameters.policy, result.deterministic_noise_bound,
            active_moduli(context.parameters, result.rns_limbs),
            context.parameters.special_modulus,
            DeterministicNoiseOperation::Rotation);
        result.identity = next_identity(context.identities);
    };
    if (reduced % half != 0) {
        one_rotation();
    }
    if (reduced >= half) {
        one_rotation();
    }
    return result;
}

Ciphertext Backend::fold(const EvalContext &context,
                         const Ciphertext &ciphertext) {
    Ciphertext result = ciphertext;
    for (std::size_t shift = 1; shift < slot_count(context); shift *= 2) {
        result = add(context, result, rotate(context, result, shift));
    }
    return result;
}

Backend::ExtCiphertext Backend::ext_add(
    const EvalContext &context, const ExtCiphertext &left,
    const ExtCiphertext &right) {
    validate_extension_pair(context, left, right,
                            "NoiseEnvelopeBackend::ext_add");
    ExtCiphertext result;
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (left[coefficient] && right[coefficient]) {
            result[coefficient] = add(
                context, *left[coefficient], *right[coefficient]);
        } else if (left[coefficient]) {
            result[coefficient] = *left[coefficient];
        } else if (right[coefficient]) {
            result[coefficient] = *right[coefficient];
        }
    }
    return result;
}

Backend::ExtCiphertext Backend::ext_sub(
    const EvalContext &context, const ExtCiphertext &left,
    const ExtCiphertext &right) {
    validate_extension_pair(context, left, right,
                            "NoiseEnvelopeBackend::ext_sub");
    ExtCiphertext result;
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (left[coefficient] && right[coefficient]) {
            if (left[coefficient]->identity ==
                right[coefficient]->identity) {
                continue;
            }
            result[coefficient] = sub(
                context, *left[coefficient], *right[coefficient]);
        } else if (left[coefficient]) {
            result[coefficient] = *left[coefficient];
        } else if (right[coefficient]) {
            result[coefficient] = negate(context, *right[coefficient]);
        }
    }
    return result;
}

Backend::ExtCiphertext Backend::ext_mul_no_relin(
    const EvalContext &context, const ExtCiphertext &left,
    const ExtCiphertext &right) {
    validate_extension_pair(context, left, right,
                            "NoiseEnvelopeBackend::ext_mul_no_relin");
    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    for (std::size_t left_degree = 0; left_degree < kExtensionDegree;
         ++left_degree) {
        if (!left[left_degree]) {
            continue;
        }
        for (std::size_t right_degree = 0; right_degree < kExtensionDegree;
             ++right_degree) {
            if (!right[right_degree]) {
                continue;
            }
            accumulate(context, coefficients[left_degree + right_degree],
                       mul_no_relin(context, *left[left_degree],
                                    *right[right_degree]));
        }
    }
    reduce_extension_polynomial(context, coefficients);

    ExtCiphertext result;
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

void Backend::ext_relinearize(const EvalContext &context,
                              ExtCiphertext &ciphertext) {
    (void)validate_extension(
        context, ciphertext, "NoiseEnvelopeBackend::ext_relinearize");
    for (auto &coefficient : ciphertext) {
        if (coefficient && coefficient->component_count > 2) {
            relinearize(context, *coefficient);
        }
    }
}

Backend::ExtCiphertext Backend::ext_mul(
    const EvalContext &context, const ExtCiphertext &left,
    const ExtCiphertext &right) {
    ExtCiphertext result = ext_mul_no_relin(context, left, right);
    ext_relinearize(context, result);
    return result;
}

Backend::ExtCiphertext Backend::ext_mul_plain(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PlainExtension &plaintext) {
    (void)validate_extension(
        context, ciphertext, "NoiseEnvelopeBackend::ext_mul_plain");
    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    for (std::size_t plain_degree = 0; plain_degree < kExtensionDegree;
         ++plain_degree) {
        for (std::size_t cipher_degree = 0;
             cipher_degree < kExtensionDegree; ++cipher_degree) {
            if (!ciphertext[cipher_degree]) {
                continue;
            }
            accumulate(context,
                       coefficients[cipher_degree + plain_degree],
                       mul_plain(context, *ciphertext[cipher_degree],
                                 plaintext[plain_degree]));
        }
    }
    reduce_extension_polynomial(context, coefficients);

    ExtCiphertext result;
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

Backend::ExtCiphertext Backend::ext_mul_plain_prepared(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    (void)validate_extension(
        context, ciphertext,
        "NoiseEnvelopeBackend::ext_mul_plain_prepared");
    for (const auto &coefficient : ciphertext) {
        if (coefficient && coefficient->rns_limbs != basis.rns_limbs) {
            throw std::invalid_argument(
                "NoiseEnvelopeBackend::ext_mul_plain_prepared: basis has "
                "the wrong level");
        }
    }
    return ext_mul_plain(context, ciphertext, basis.plaintext);
}

Backend::ExtCiphertext Backend::promote_plain_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    if (ciphertext.rns_limbs != basis.rns_limbs) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::promote_plain_prepared: basis has the "
            "wrong level");
    }
    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] = mul_plain(
            context, ciphertext, basis.plaintext[coefficient]);
    }
    return result;
}

PreparedBasisStorageStats
Backend::prepared_extension_slot_basis_storage(
    const PreparedExtensionSlotBasis &basis) {
    return PreparedBasisStorageStats{
        .level_representations = 0,
        .ntt_coefficient_bytes = 0,
        .host_basis_bytes =
            basis.plaintext.size() * basis.plaintext.front().size() *
            sizeof(Fp),
    };
}

Backend::ExtCiphertext Backend::ext_mul_plain_scalar(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PlainExtensionScalar &plaintext) {
    (void)validate_extension(
        context, ciphertext,
        "NoiseEnvelopeBackend::ext_mul_plain_scalar");
    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    // Do not skip zero coefficients. The envelope represents every
    // challenge-dependent term by its worst-case nonzero topology.
    for (std::size_t plain_degree = 0;
         plain_degree < kExtensionDegree; ++plain_degree) {
        for (std::size_t cipher_degree = 0;
             cipher_degree < kExtensionDegree; ++cipher_degree) {
            if (!ciphertext[cipher_degree]) {
                continue;
            }
            accumulate(context,
                       coefficients[cipher_degree + plain_degree],
                       mul_plain_scalar(context,
                                        *ciphertext[cipher_degree],
                                        plaintext[plain_degree]));
        }
    }
    reduce_extension_polynomial(context, coefficients);

    ExtCiphertext result;
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

void Backend::mod_switch_to_next(const EvalContext &context,
                                 Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::mod_switch_to_next");
    if (ciphertext.rns_limbs == 1) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::mod_switch_to_next: already bottom");
    }
    ciphertext.deterministic_noise_bound = bound_modulus_switch(
        context.parameters.policy, ciphertext.deterministic_noise_bound,
        ciphertext.component_count,
        active_moduli(context.parameters, ciphertext.rns_limbs));
    --ciphertext.rns_limbs;
    ciphertext.identity = next_identity(context.identities);
}

void Backend::mod_switch_to_lowest(const EvalContext &context,
                                   Ciphertext &ciphertext) {
    while (ciphertext.rns_limbs > 1) {
        mod_switch_to_next(context, ciphertext);
    }
}

std::size_t Backend::remaining_mult_depth(const EvalContext &context,
                                          const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::remaining_mult_depth");
    return ciphertext.rns_limbs - 1;
}

std::size_t Backend::rns_limb_count(const EvalContext &context,
                                    const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::rns_limb_count");
    return ciphertext.rns_limbs;
}

std::size_t Backend::coeff_modulus_bits(const EvalContext &context,
                                        const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::coeff_modulus_bits");
    std::size_t result = 0;
    for (const std::uint64_t modulus :
         active_moduli(context.parameters, ciphertext.rns_limbs)) {
        result += std::bit_width(modulus);
    }
    return result;
}

int Backend::estimated_noise_bits(const EvalContext &context,
                                  const Ciphertext &ciphertext) {
    (void)context;
    (void)ciphertext;
    // Transport compaction should be controlled solely by its explicit RNS
    // reserve. The exact no-wrap test is applied to the resulting bound.
    return std::numeric_limits<int>::max();
}

std::size_t Backend::slot_count(const EvalContext &context) {
    return context.parameters.policy.ring_degree;
}

std::size_t Backend::slot_count(const ClientContext &context) {
    return context.parameters.policy.ring_degree;
}

std::vector<std::uint8_t> Backend::serialize(
    const Ciphertext &ciphertext) {
    std::vector<std::uint8_t> result{'L', 'M', '/', 'N', 'O', 'I', 'S', 'E',
                                     '/', 'V', '1'};
    append_u64(result, ciphertext.identity);
    append_u64(result, static_cast<std::uint64_t>(ciphertext.rns_limbs));
    append_u64(result,
               static_cast<std::uint64_t>(ciphertext.component_count));
    append_u64(result, static_cast<std::uint64_t>(
                           ciphertext.deterministic_noise_bound
                               .partial_decryption_bound.bit_count()));
    append_u64(result, static_cast<std::uint64_t>(
                           ciphertext.deterministic_noise_bound
                               .operation_count));
    return result;
}

void Backend::normalize_for_coefficient_commitment(
    const EvalContext &context, Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::normalize");
    if (ciphertext.rns_limbs != 1 || ciphertext.component_count != 2) {
        throw std::invalid_argument(
            "NoiseEnvelopeBackend::normalize: expected size two at bottom");
    }
}

bool Backend::correction_factor_is_one(const Ciphertext &) { return true; }

bool Backend::is_normalized_for_coefficient_commitment(
    const Ciphertext &ciphertext) {
    return ciphertext.rns_limbs == 1 && ciphertext.component_count == 2;
}

std::uint64_t Backend::partial_decryption_infinity_norm(
    const ClientContext &context, const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "NoiseEnvelopeBackend::partial_decryption_norm");
    if (!is_normalized_for_coefficient_commitment(ciphertext) ||
        !ciphertext.deterministic_noise_bound.partial_decryption_bound
             .fits_u64()) {
        throw std::overflow_error(
            "NoiseEnvelopeBackend: bound is unavailable as uint64");
    }
    return ciphertext.deterministic_noise_bound.partial_decryption_bound
        .to_u64();
}

bool Backend::partial_decryption_within_bound(
    const ClientContext &context, const Ciphertext &ciphertext,
    std::uint64_t threshold) {
    return partial_decryption_infinity_norm(context, ciphertext) <= threshold;
}

} // namespace laminate::fhe
