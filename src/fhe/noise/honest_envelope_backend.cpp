/// @file honest_envelope_backend.cpp
/// @brief Exact integer implementation of the honest operational envelope.

#include "laminate/fhe/noise/honest_envelope_backend.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace laminate::fhe {
namespace {

using Backend = HonestNoiseEnvelopeBackend;
using Ciphertext = Backend::Ciphertext;
using EvalContext = Backend::EvalContext;
using OptionalCiphertext = std::optional<Ciphertext>;

std::span<const std::uint64_t> active_moduli(
    const HonestNoiseEnvelopeParameters &parameters, std::size_t limbs) {
    if (limbs == 0 || limbs > parameters.data_moduli.size()) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend: invalid RNS limb count");
    }
    return std::span<const std::uint64_t>(parameters.data_moduli)
        .first(limbs);
}

std::uint64_t take_sequence(std::uint64_t &next, const char *description) {
    if (next == 0 || next == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(std::string(
                                      "HonestNoiseEnvelopeBackend: ") +
                                  description + " exhausted");
    }
    return next++;
}

std::uint64_t next_identity(
    const std::shared_ptr<Backend::SequenceState> &state) {
    if (!state) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend: missing sequence state");
    }
    return take_sequence(state->next_identity, "ciphertext identity");
}

std::uint64_t next_operation(
    const std::shared_ptr<Backend::SequenceState> &state) {
    if (!state) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend: missing sequence state");
    }
    return take_sequence(state->next_operation, "operation sequence");
}

std::optional<HonestNoiseEnvelopeFailure> earlier_failure(
    const std::optional<HonestNoiseEnvelopeFailure> &left,
    const std::optional<HonestNoiseEnvelopeFailure> &right = std::nullopt) {
    if (!left) {
        return right;
    }
    if (!right || left->operation_sequence <= right->operation_sequence) {
        return left;
    }
    return right;
}

template <typename Context>
void validate_context(const Context &context, const char *operation) {
    if (!context.sequences ||
        !(context.parameters == context.sequences->bound_parameters)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": backend context was modified");
    }
}

template <typename Context>
Ciphertext make_ciphertext(
    const Context &context, NaturalMagnitude canonical_error_bound,
    std::size_t limbs, std::size_t components,
    HonestNoiseEnvelopeOperation operation, std::size_t input_limbs,
    std::size_t operation_count,
    std::optional<HonestNoiseEnvelopeFailure> inherited_failure =
        std::nullopt) {
    validate_context(context, "HonestNoiseEnvelopeBackend::make_ciphertext");
    if (canonical_error_bound.is_zero() || components < 2) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend: malformed live ciphertext bound");
    }
    const std::span<const std::uint64_t> moduli =
        active_moduli(context.parameters, limbs);
    const std::uint64_t sequence = next_operation(context.sequences);
    if (!inherited_failure &&
        !honest_noise_fits_active_modulus(
            context.parameters.plaintext_modulus, canonical_error_bound,
            moduli)) {
        inherited_failure = HonestNoiseEnvelopeFailure{
            .operation = operation,
            .operation_sequence = sequence,
            .input_rns_limbs = input_limbs,
            .output_rns_limbs = limbs,
            .canonical_error_bound = canonical_error_bound,
            .active_modulus_product_bits =
                NaturalMagnitude::product(moduli).bit_count(),
        };
    }
    return Ciphertext{
        .canonical_error_bound = std::move(canonical_error_bound),
        .rns_limbs = limbs,
        .component_count = components,
        .identity = next_identity(context.sequences),
        .context_token = context.sequences,
        .operation_count = operation_count,
        .last_operation_sequence = sequence,
        .first_failure = std::move(inherited_failure),
    };
}

template <typename Context>
void validate_ciphertext(const Context &context,
                         const Ciphertext &ciphertext,
                         const char *operation) {
    validate_context(context, operation);
    if (!context.sequences || !ciphertext.context_token ||
        context.sequences.get() != ciphertext.context_token.get()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext context mismatch");
    }
    (void)active_moduli(context.parameters, ciphertext.rns_limbs);
    if (ciphertext.canonical_error_bound.is_zero() ||
        ciphertext.component_count < 2 || ciphertext.identity == 0 ||
        ciphertext.last_operation_sequence == 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": malformed live ciphertext bound");
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

NaturalMagnitude debit(const NaturalMagnitude &input, std::size_t bits) {
    return NaturalMagnitude::shift_left(input, bits);
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
                        "HonestNoiseEnvelopeBackend::align");
    validate_ciphertext(context, right,
                        "HonestNoiseEnvelopeBackend::align");
    Ciphertext aligned_left = left;
    Ciphertext aligned_right = right;
    const std::size_t target =
        std::min(aligned_left.rns_limbs, aligned_right.rns_limbs);
    switch_to_limbs(context, aligned_left, target);
    switch_to_limbs(context, aligned_right, target);
    return {std::move(aligned_left), std::move(aligned_right)};
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
                    : Backend::mul_plain_scalar(
                          context, negative, Fp(modulus_coefficient));
            accumulate(context,
                       coefficients[degree - kExtensionDegree +
                                    coefficient],
                       std::move(term));
        }
    }
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_size(std::vector<std::uint8_t> &output, std::size_t value,
                 const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " does not fit u64");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_label(std::vector<std::uint8_t> &output,
                  std::string_view label) {
    append_size(output, label.size(),
                "honest noise parameter encoding label length");
    output.insert(output.end(), label.begin(), label.end());
}

void append_magnitude(std::vector<std::uint8_t> &output,
                      const NaturalMagnitude &magnitude) {
    const std::vector<std::uint8_t> encoded =
        encode_canonical(magnitude);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

std::size_t checked_increment(std::size_t value) {
    if (value == std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(
            "HonestNoiseEnvelopeBackend: operation count overflow");
    }
    return value + 1;
}

std::size_t checked_binary_count(const Ciphertext &left,
                                 const Ciphertext &right) {
    return checked_increment(
        std::max(left.operation_count, right.operation_count));
}

} // namespace

void HonestNoiseEnvelopeParameters::validate() const {
    if (ring_degree < 2 || !std::has_single_bit(ring_degree) ||
        plaintext_modulus != kBaseFieldOrder || data_moduli.empty() ||
        fresh_canonical_error_bound.is_zero() ||
        switch_rounding_error_bound.is_zero()) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend: invalid public parameters");
    }
    if (ctct_relinearized_debit_bits >
            kMaximumHonestNoiseEnvelopeDebitBits ||
        plaintext_multiplication_debit_bits >
            kMaximumHonestNoiseEnvelopeDebitBits ||
        rotation_debit_bits > kMaximumHonestNoiseEnvelopeDebitBits) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend: operation debit is too large");
    }
    for (const std::uint64_t modulus : data_moduli) {
        if (modulus < 3 || modulus % 2 == 0) {
            throw std::invalid_argument(
                "HonestNoiseEnvelopeBackend: data moduli must be odd");
        }
    }
}

std::vector<std::uint8_t>
encode_canonical(const HonestNoiseEnvelopeParameters &parameters) {
    parameters.validate();

    std::vector<std::uint8_t> output;
    append_label(output,
                 "LaminateImpl/HonestNoiseEnvelopeParameters/v1");
    append_size(output, parameters.ring_degree,
                "honest noise parameter ring degree");
    append_u64(output, parameters.plaintext_modulus);
    append_magnitude(output, parameters.fresh_canonical_error_bound);
    append_size(output, parameters.ctct_relinearized_debit_bits,
                "honest noise CT-CT debit");
    append_size(output, parameters.plaintext_multiplication_debit_bits,
                "honest noise plaintext-multiplication debit");
    append_size(output, parameters.rotation_debit_bits,
                "honest noise rotation debit");
    append_magnitude(output, parameters.switch_rounding_error_bound);
    append_size(output, parameters.data_moduli.size(),
                "honest noise data-modulus count");
    for (const std::uint64_t modulus : parameters.data_moduli) {
        append_u64(output, modulus);
    }
    return output;
}

Digest honest_noise_envelope_parameters_digest(
    const HonestNoiseEnvelopeParameters &parameters) {
    const std::vector<std::uint8_t> encoded =
        encode_canonical(parameters);
    return sha256(encoded);
}

const char *honest_noise_envelope_operation_name(
    HonestNoiseEnvelopeOperation operation) {
    switch (operation) {
    case HonestNoiseEnvelopeOperation::SourceCiphertext:
        return "source-ciphertext";
    case HonestNoiseEnvelopeOperation::FreshEncryption:
        return "fresh-encryption";
    case HonestNoiseEnvelopeOperation::Negation:
        return "negation";
    case HonestNoiseEnvelopeOperation::Addition:
        return "addition";
    case HonestNoiseEnvelopeOperation::Subtraction:
        return "subtraction";
    case HonestNoiseEnvelopeOperation::PlaintextAddition:
        return "plaintext-addition";
    case HonestNoiseEnvelopeOperation::PlaintextMultiplication:
        return "plaintext-multiplication";
    case HonestNoiseEnvelopeOperation::CiphertextMultiplication:
        return "ciphertext-multiplication";
    case HonestNoiseEnvelopeOperation::Relinearization:
        return "relinearization";
    case HonestNoiseEnvelopeOperation::Rotation:
        return "rotation";
    case HonestNoiseEnvelopeOperation::ModulusSwitch:
        return "modulus-switch";
    }
    return "unknown";
}

NaturalMagnitude honest_noise_phase_bound(
    std::uint64_t plaintext_modulus,
    const NaturalMagnitude &canonical_error_bound) {
    if (plaintext_modulus < 3 || plaintext_modulus % 2 == 0) {
        throw std::invalid_argument(
            "honest noise phase: plaintext modulus must be odd");
    }
    return NaturalMagnitude::add(
        NaturalMagnitude::multiply(canonical_error_bound,
                                   plaintext_modulus),
        NaturalMagnitude((plaintext_modulus - 1) / 2));
}

bool honest_noise_fits_active_modulus(
    std::uint64_t plaintext_modulus,
    const NaturalMagnitude &canonical_error_bound,
    std::span<const std::uint64_t> active_data_moduli) {
    if (active_data_moduli.empty()) {
        throw std::invalid_argument(
            "honest noise fit: active modulus list is empty");
    }
    const NaturalMagnitude phase = honest_noise_phase_bound(
        plaintext_modulus, canonical_error_bound);
    return NaturalMagnitude::multiply(phase, std::uint64_t{2}) <
           NaturalMagnitude::product(active_data_moduli);
}

Backend::Contexts Backend::create(HonestNoiseEnvelopeParameters parameters) {
    parameters.validate();
    auto sequences = std::make_shared<SequenceState>(parameters);
    return Contexts{
        EvalContext{parameters, sequences},
        ClientContext{std::move(parameters), std::move(sequences)},
    };
}

Ciphertext Backend::source_ciphertext(
    const EvalContext &context, NaturalMagnitude canonical_error_bound,
    std::size_t rns_limbs, std::size_t component_count) {
    return make_ciphertext(
        context, std::move(canonical_error_bound), rns_limbs,
        component_count, HonestNoiseEnvelopeOperation::SourceCiphertext,
        rns_limbs, 0);
}

Ciphertext Backend::encrypt(const ClientContext &context,
                            const SlotVector &slots) {
    if (slots.size() > slot_count(context)) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::encrypt: plaintext exceeds slots");
    }
    return make_ciphertext(
        context, context.parameters.fresh_canonical_error_bound,
        context.parameters.data_moduli.size(), 2,
        HonestNoiseEnvelopeOperation::FreshEncryption,
        context.parameters.data_moduli.size(), 0);
}

SlotVector Backend::decrypt(const ClientContext &context,
                            const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::decrypt");
    return SlotVector(slot_count(context), Fp::zero());
}

Ciphertext Backend::negate(const EvalContext &context,
                           const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::negate");
    return make_ciphertext(
        context, ciphertext.canonical_error_bound, ciphertext.rns_limbs,
        ciphertext.component_count, HonestNoiseEnvelopeOperation::Negation,
        ciphertext.rns_limbs, checked_increment(ciphertext.operation_count),
        ciphertext.first_failure);
}

Ciphertext Backend::add(const EvalContext &context,
                        const Ciphertext &left,
                        const Ciphertext &right) {
    auto [a, b] = align(context, left, right);
    return make_ciphertext(
        context,
        NaturalMagnitude::add(a.canonical_error_bound,
                              b.canonical_error_bound),
        a.rns_limbs, std::max(a.component_count, b.component_count),
        HonestNoiseEnvelopeOperation::Addition, a.rns_limbs,
        checked_binary_count(a, b),
        earlier_failure(a.first_failure, b.first_failure));
}

bool Backend::same_ciphertext(const EvalContext &context,
                              const Ciphertext &left,
                              const Ciphertext &right) {
    validate_ciphertext(context, left,
                        "HonestNoiseEnvelopeBackend::same_ciphertext");
    validate_ciphertext(context, right,
                        "HonestNoiseEnvelopeBackend::same_ciphertext");
    if (left.identity != right.identity) {
        return false;
    }
    if (left.rns_limbs != right.rns_limbs ||
        left.component_count != right.component_count ||
        !(left.canonical_error_bound == right.canonical_error_bound) ||
        left.operation_count != right.operation_count ||
        left.last_operation_sequence != right.last_operation_sequence ||
        left.first_failure != right.first_failure) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::same_ciphertext: inconsistent "
            "identity");
    }
    return true;
}

Ciphertext Backend::sub(const EvalContext &context,
                        const Ciphertext &left,
                        const Ciphertext &right) {
    if (same_ciphertext(context, left, right)) {
        throw std::logic_error(
            "HonestNoiseEnvelopeBackend::sub: exact cancellation is a "
            "public FheValue zero, not a ciphertext");
    }
    auto [a, b] = align(context, left, right);
    return make_ciphertext(
        context,
        NaturalMagnitude::add(a.canonical_error_bound,
                              b.canonical_error_bound),
        a.rns_limbs, std::max(a.component_count, b.component_count),
        HonestNoiseEnvelopeOperation::Subtraction, a.rns_limbs,
        checked_binary_count(a, b),
        earlier_failure(a.first_failure, b.first_failure));
}

Ciphertext Backend::mul_no_relin(const EvalContext &context,
                                 const Ciphertext &left,
                                 const Ciphertext &right) {
    validate_ciphertext(context, left,
                        "HonestNoiseEnvelopeBackend::mul_no_relin");
    validate_ciphertext(context, right,
                        "HonestNoiseEnvelopeBackend::mul_no_relin");
    if (left.component_count != 2 || right.component_count != 2) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::mul_no_relin: inputs must be size "
            "two");
    }
    auto [a, b] = align(context, left, right);
    const NaturalMagnitude &maximum =
        a.canonical_error_bound < b.canonical_error_bound
            ? b.canonical_error_bound
            : a.canonical_error_bound;
    return make_ciphertext(
        context,
        debit(maximum,
              context.parameters.ctct_relinearized_debit_bits),
        a.rns_limbs, 3,
        HonestNoiseEnvelopeOperation::CiphertextMultiplication,
        a.rns_limbs, checked_binary_count(a, b),
        earlier_failure(a.first_failure, b.first_failure));
}

void Backend::relinearize(const EvalContext &context,
                          Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::relinearize");
    if (ciphertext.component_count <= 2) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::relinearize: already size two");
    }
    ciphertext = make_ciphertext(
        context, ciphertext.canonical_error_bound, ciphertext.rns_limbs, 2,
        HonestNoiseEnvelopeOperation::Relinearization,
        ciphertext.rns_limbs,
        checked_increment(ciphertext.operation_count),
        ciphertext.first_failure);
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
            "HonestNoiseEnvelopeBackend::add_plain: plaintext exceeds "
            "slots");
    }
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::add_plain");
    return make_ciphertext(
        context, ciphertext.canonical_error_bound, ciphertext.rns_limbs,
        ciphertext.component_count,
        HonestNoiseEnvelopeOperation::PlaintextAddition,
        ciphertext.rns_limbs, checked_increment(ciphertext.operation_count),
        ciphertext.first_failure);
}

Ciphertext Backend::add_plain_scalar(const EvalContext &context,
                                     const Ciphertext &ciphertext,
                                     const Fp &plaintext) {
    (void)plaintext;
    return add_plain(context, ciphertext, {});
}

Ciphertext Backend::mul_plain(const EvalContext &context,
                              const Ciphertext &ciphertext,
                              const SlotVector &plaintext) {
    if (plaintext.size() > slot_count(context)) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::mul_plain: plaintext exceeds "
            "slots");
    }
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::mul_plain");
    return make_ciphertext(
        context,
        debit(ciphertext.canonical_error_bound,
              context.parameters.plaintext_multiplication_debit_bits),
        ciphertext.rns_limbs, ciphertext.component_count,
        HonestNoiseEnvelopeOperation::PlaintextMultiplication,
        ciphertext.rns_limbs, checked_increment(ciphertext.operation_count),
        ciphertext.first_failure);
}

Ciphertext Backend::mul_plain_scalar(const EvalContext &context,
                                     const Ciphertext &ciphertext,
                                     const Fp &plaintext) {
    (void)plaintext;
    return mul_plain(context, ciphertext, {});
}

Backend::PreparedSlotBasis Backend::prepare_slot_basis(
    const EvalContext &context, const SlotVector &basis) {
    if (basis.size() != slot_count(context)) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::prepare_slot_basis: basis must "
            "fill all slots");
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
                        "HonestNoiseEnvelopeBackend::prepare_level_slot_basis");
    if (basis.size() != slot_count(context)) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::prepare_level_slot_basis: basis "
            "must fill all slots");
    }
    return PreparedLevelSlotBasis{basis, level_reference.rns_limbs};
}

Ciphertext Backend::mul_plain_level_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedLevelSlotBasis &basis) {
    if (ciphertext.rns_limbs != basis.rns_limbs) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::mul_plain_level_prepared: wrong "
            "level");
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
            "HonestNoiseEnvelopeBackend::preprocess_fixed_message_cells: "
            "too few slots");
    }
}

Ciphertext Backend::mul_plain_fixed_message_cell(
    const EvalContext &context, const Ciphertext &ciphertext,
    std::size_t cell) {
    if (cell >= kFixedMessageCellCount) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::mul_plain_fixed_message_cell: "
            "cell is out of range");
    }
    // HonestNoiseEnvelopeBackend's plaintext-multiplication debit depends
    // only on the operation class, not the materialized plaintext value.
    return mul_plain(context, ciphertext, {});
}

Backend::PreparedExtensionSlotBasis
Backend::prepare_extension_slot_basis(
    const EvalContext &context, const Ciphertext &level_reference,
    const PlainExtension &basis) {
    validate_ciphertext(
        context, level_reference,
        "HonestNoiseEnvelopeBackend::prepare_extension_slot_basis");
    for (const SlotVector &coefficient : basis) {
        if (coefficient.size() != slot_count(context)) {
            throw std::invalid_argument(
                "HonestNoiseEnvelopeBackend::prepare_extension_slot_basis: "
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
                        "HonestNoiseEnvelopeBackend::rotate");
    if (steps % slot_count(context) == 0) {
        return ciphertext;
    }
    return make_ciphertext(
        context,
        debit(ciphertext.canonical_error_bound,
              context.parameters.rotation_debit_bits),
        ciphertext.rns_limbs, ciphertext.component_count,
        HonestNoiseEnvelopeOperation::Rotation, ciphertext.rns_limbs,
        checked_increment(ciphertext.operation_count),
        ciphertext.first_failure);
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
                            "HonestNoiseEnvelopeBackend::ext_add");
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
                            "HonestNoiseEnvelopeBackend::ext_sub");
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
                            "HonestNoiseEnvelopeBackend::ext_mul_no_relin");
    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    for (std::size_t left_degree = 0; left_degree < kExtensionDegree;
         ++left_degree) {
        if (!left[left_degree]) {
            continue;
        }
        for (std::size_t right_degree = 0;
             right_degree < kExtensionDegree; ++right_degree) {
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
        context, ciphertext,
        "HonestNoiseEnvelopeBackend::ext_relinearize");
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
        context, ciphertext,
        "HonestNoiseEnvelopeBackend::ext_mul_plain");
    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    for (std::size_t plain_degree = 0;
         plain_degree < kExtensionDegree; ++plain_degree) {
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
        "HonestNoiseEnvelopeBackend::ext_mul_plain_prepared");
    for (const auto &coefficient : ciphertext) {
        if (coefficient && coefficient->rns_limbs != basis.rns_limbs) {
            throw std::invalid_argument(
                "HonestNoiseEnvelopeBackend::ext_mul_plain_prepared: basis "
                "has the wrong level");
        }
    }
    return ext_mul_plain(context, ciphertext, basis.plaintext);
}

Backend::ExtCiphertext Backend::promote_plain_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    if (ciphertext.rns_limbs != basis.rns_limbs) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::promote_plain_prepared: basis has "
            "the wrong level");
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
        "HonestNoiseEnvelopeBackend::ext_mul_plain_scalar");
    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    // Zero challenge coefficients are intentionally charged as operations.
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
                        "HonestNoiseEnvelopeBackend::mod_switch_to_next");
    if (ciphertext.rns_limbs == 1) {
        throw std::invalid_argument(
            "HonestNoiseEnvelopeBackend::mod_switch_to_next: already "
            "bottom");
    }
    const std::size_t input_limbs = ciphertext.rns_limbs;
    const std::uint64_t dropped =
        context.parameters.data_moduli[input_limbs - 1];
    NaturalMagnitude output = NaturalMagnitude::add(
        NaturalMagnitude::divide_ceil(ciphertext.canonical_error_bound,
                                      dropped),
        context.parameters.switch_rounding_error_bound);
    ciphertext = make_ciphertext(
        context, std::move(output), input_limbs - 1,
        ciphertext.component_count,
        HonestNoiseEnvelopeOperation::ModulusSwitch, input_limbs,
        checked_increment(ciphertext.operation_count),
        ciphertext.first_failure);
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
                        "HonestNoiseEnvelopeBackend::remaining_mult_depth");
    return ciphertext.rns_limbs - 1;
}

std::size_t Backend::rns_limb_count(const EvalContext &context,
                                    const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::rns_limb_count");
    return ciphertext.rns_limbs;
}

std::size_t Backend::coeff_modulus_bits(const EvalContext &context,
                                        const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::coeff_modulus_bits");
    return NaturalMagnitude::product(
               active_moduli(context.parameters, ciphertext.rns_limbs))
        .bit_count();
}

int Backend::estimated_noise_bits(const EvalContext &context,
                                  const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::estimated_noise_bits");
    const NaturalMagnitude doubled_phase = NaturalMagnitude::multiply(
        phase_bound(context, ciphertext), std::uint64_t{2});
    const std::size_t modulus_bits = coeff_modulus_bits(context, ciphertext);
    const std::size_t used_bits = doubled_phase.bit_count();
    if (!fits_active_modulus(context, ciphertext) ||
        modulus_bits <= used_bits) {
        return 0;
    }
    const std::size_t margin = modulus_bits - used_bits;
    return margin > static_cast<std::size_t>(std::numeric_limits<int>::max())
               ? std::numeric_limits<int>::max()
               : static_cast<int>(margin);
}

std::size_t Backend::slot_count(const EvalContext &context) {
    validate_context(context, "HonestNoiseEnvelopeBackend::slot_count");
    return context.parameters.ring_degree;
}

std::size_t Backend::slot_count(const ClientContext &context) {
    validate_context(context, "HonestNoiseEnvelopeBackend::slot_count");
    return context.parameters.ring_degree;
}

std::uint64_t Backend::plaintext_modulus(const EvalContext &context) {
    validate_context(context,
                     "HonestNoiseEnvelopeBackend::plaintext_modulus");
    return context.parameters.plaintext_modulus;
}

std::vector<std::uint8_t> Backend::serialize(
    const Ciphertext &ciphertext) {
    std::vector<std::uint8_t> result{
        'L', 'M', '/', 'H', 'O', 'N', 'E', 'S', 'T', '/', 'V', '1'};
    append_u64(result, ciphertext.identity);
    append_u64(result, static_cast<std::uint64_t>(ciphertext.rns_limbs));
    append_u64(result,
               static_cast<std::uint64_t>(ciphertext.component_count));
    append_u64(result, static_cast<std::uint64_t>(
                           ciphertext.canonical_error_bound.bit_count()));
    append_u64(result,
               static_cast<std::uint64_t>(ciphertext.operation_count));
    append_u64(result, ciphertext.last_operation_sequence);
    result.push_back(ciphertext.first_failure ? 1 : 0);
    if (ciphertext.first_failure) {
        result.push_back(static_cast<std::uint8_t>(
            ciphertext.first_failure->operation));
        append_u64(result,
                   ciphertext.first_failure->operation_sequence);
        append_u64(result, static_cast<std::uint64_t>(
                               ciphertext.first_failure->output_rns_limbs));
    }
    return result;
}

NaturalMagnitude Backend::phase_bound(const EvalContext &context,
                                      const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::phase_bound");
    return honest_noise_phase_bound(
        context.parameters.plaintext_modulus,
        ciphertext.canonical_error_bound);
}

bool Backend::fits_active_modulus(const EvalContext &context,
                                  const Ciphertext &ciphertext) {
    validate_ciphertext(context, ciphertext,
                        "HonestNoiseEnvelopeBackend::fits_active_modulus");
    return honest_noise_fits_active_modulus(
        context.parameters.plaintext_modulus,
        ciphertext.canonical_error_bound,
        active_moduli(context.parameters, ciphertext.rns_limbs));
}

void Backend::observe_base_message_normalization(
    const EvalContext &context, const ExtCiphertext &before,
    const ExtCiphertext &after) {
    (void)validate_extension(
        context, before,
        "HonestNoiseEnvelopeBackend::observe_normalization/input");
    (void)validate_extension(
        context, after,
        "HonestNoiseEnvelopeBackend::observe_normalization/output");
    HonestBaseNormalizationRecord record;
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (before[coefficient].has_value() !=
            after[coefficient].has_value()) {
            throw std::invalid_argument(
                "HonestNoiseEnvelopeBackend::observe_normalization: "
                "extension support changed");
        }
        if (!before[coefficient]) {
            continue;
        }
        const Ciphertext &input = *before[coefficient];
        const Ciphertext &output = *after[coefficient];
        record.coefficients[coefficient] =
            HonestBaseNormalizationCoefficientRecord{
                .present = true,
                .input_canonical_error_bound =
                    input.canonical_error_bound,
                .output_canonical_error_bound =
                    output.canonical_error_bound,
                .input_rns_limbs = input.rns_limbs,
                .output_rns_limbs = output.rns_limbs,
                .input_component_count =
                    input.component_count,
                .output_component_count =
                    output.component_count,
                .input_identity = input.identity,
                .output_identity = output.identity,
                .input_first_failure =
                    input.first_failure,
                .output_first_failure =
                    output.first_failure,
            };
    }
    context.sequences->base_normalization_records.push_back(
        std::move(record));
}

std::span<const HonestBaseNormalizationRecord>
Backend::base_message_normalization_records(
    const EvalContext &context) {
    validate_context(
        context,
        "HonestNoiseEnvelopeBackend::normalization_records");
    return context.sequences->base_normalization_records;
}

void Backend::clear_base_message_normalization_records(
    const EvalContext &context) {
    validate_context(
        context,
        "HonestNoiseEnvelopeBackend::clear_normalization_records");
    context.sequences->base_normalization_records.clear();
}

} // namespace laminate::fhe
