/// @file telemetry.cpp
/// @brief SEAL operation counters and context/ciphertext metadata queries.

#include "arithmetic_internal.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace laminate::fhe {

using seal_detail::chain_index;
using seal_detail::signed_remaining_bits;

const SealBackend::OperationCounts::LimbBuckets &
SealBackend::OperationCounts::buckets(OperationKind kind) const {
    return by_kind.at(static_cast<std::size_t>(kind));
}

std::uint64_t
SealBackend::OperationCounts::calls(OperationKind kind) const {
    std::uint64_t result = 0;
    for (const auto &[limbs, count] : buckets(kind)) {
        (void)limbs;
        result += count;
    }
    return result;
}

std::uint64_t
SealBackend::OperationCounts::limb_operations(OperationKind kind) const {
    std::uint64_t result = 0;
    for (const auto &[limbs, count] : buckets(kind)) {
        result += static_cast<std::uint64_t>(limbs) * count;
    }
    return result;
}

std::size_t SealBackend::remaining_mult_depth(const EvalContext &context,
                                  const Ciphertext &ciphertext) {
    return chain_index(context, ciphertext);
}

std::size_t SealBackend::rns_limb_count(const EvalContext &context,
                                        const Ciphertext &ciphertext) {
    const auto data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!data) {
        throw std::invalid_argument(
            "SealBackend::rns_limb_count: unknown ciphertext parameters");
    }
    return data->parms().coeff_modulus().size();
}

std::size_t SealBackend::rns_limb_count(
    const PublicVerifierContext &context,
    const Ciphertext &ciphertext) {
    const auto data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!data) {
        throw std::invalid_argument(
            "SealBackend::rns_limb_count(verifier): unknown ciphertext "
            "parameters");
    }
    return data->parms().coeff_modulus().size();
}

std::size_t SealBackend::coeff_modulus_bits(
    const EvalContext &context, const Ciphertext &ciphertext) {
    const auto data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!data) {
        throw std::invalid_argument(
            "SealBackend::coeff_modulus_bits: unknown ciphertext parameters");
    }
    std::size_t result = 0;
    for (const seal::Modulus &modulus : data->parms().coeff_modulus()) {
        result += static_cast<std::size_t>(modulus.bit_count());
    }
    return result;
}

int SealBackend::estimated_noise_bits(const EvalContext &context,
                                      const Ciphertext &ciphertext) {
    return signed_remaining_bits(coeff_modulus_bits(context, ciphertext),
                                 ciphertext.noise_loss_bits);
}

std::size_t SealBackend::slot_count(const EvalContext &context) {
    return context.encoder->slot_count();
}

std::size_t SealBackend::slot_count(const ClientContext &context) {
    return context.encoder->slot_count();
}

std::size_t SealBackend::slot_count(
    const PublicVerifierContext &context) {
    if (!context.encoder) {
        throw std::invalid_argument(
            "SealBackend::slot_count(verifier): encoder is missing");
    }
    return context.encoder->slot_count();
}

int SealBackend::invariant_noise_budget(const ClientContext &context,
                                        const Ciphertext &ciphertext) {
    return context.decryptor->invariant_noise_budget(ciphertext.raw);
}

std::vector<std::uint64_t>
SealBackend::coefficient_moduli(const EvalContext &context) {
    std::vector<std::uint64_t> result;
    const auto &moduli =
        context.context->key_context_data()->parms().coeff_modulus();
    result.reserve(moduli.size());
    for (const seal::Modulus &modulus : moduli) {
        result.push_back(modulus.value());
    }
    return result;
}

std::vector<std::uint64_t> SealBackend::data_coefficient_moduli(
    const EvalContext &context, const Ciphertext &ciphertext) {
    const auto data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!data) {
        throw std::invalid_argument(
            "SealBackend::data_coefficient_moduli: unknown ciphertext "
            "parameters");
    }
    std::vector<std::uint64_t> result;
    const auto &moduli = data->parms().coeff_modulus();
    result.reserve(moduli.size());
    for (const seal::Modulus &modulus : moduli) {
        result.push_back(modulus.value());
    }
    return result;
}

std::vector<std::uint64_t> SealBackend::data_coefficient_moduli(
    const ClientContext &context, const Ciphertext &ciphertext) {
    const auto data =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!data) {
        throw std::invalid_argument(
            "SealBackend::data_coefficient_moduli(client): unknown "
            "ciphertext parameters");
    }
    std::vector<std::uint64_t> result;
    const auto &moduli = data->parms().coeff_modulus();
    result.reserve(moduli.size());
    for (const seal::Modulus &modulus : moduli) {
        result.push_back(modulus.value());
    }
    return result;
}

std::size_t SealBackend::fresh_ciphertext_modulus_bits(
    const EvalContext &context) {
    const auto data = context.context->first_context_data();
    if (!data) {
        throw std::logic_error(
            "SealBackend::fresh_ciphertext_modulus_bits: missing context data");
    }
    return static_cast<std::size_t>(
        data->total_coeff_modulus_bit_count());
}

std::size_t SealBackend::fresh_ciphertext_modulus_width_sum_bits(
    const EvalContext &context) {
    const auto data = context.context->first_context_data();
    if (!data) {
        throw std::logic_error(
            "SealBackend::fresh_ciphertext_modulus_width_sum_bits: missing "
            "context data");
    }
    std::size_t result = 0;
    for (const seal::Modulus &modulus : data->parms().coeff_modulus()) {
        result += static_cast<std::size_t>(modulus.bit_count());
    }
    return result;
}

std::size_t SealBackend::key_modulus_bits(const EvalContext &context) {
    const auto data = context.context->key_context_data();
    if (!data) {
        throw std::logic_error(
            "SealBackend::key_modulus_bits: missing context data");
    }
    return static_cast<std::size_t>(
        data->total_coeff_modulus_bit_count());
}

std::size_t SealBackend::key_modulus_width_sum_bits(
    const EvalContext &context) {
    const auto data = context.context->key_context_data();
    if (!data) {
        throw std::logic_error(
            "SealBackend::key_modulus_width_sum_bits: missing context data");
    }
    std::size_t result = 0;
    for (const seal::Modulus &modulus : data->parms().coeff_modulus()) {
        result += static_cast<std::size_t>(modulus.bit_count());
    }
    return result;
}

void SealBackend::reset_counts(const EvalContext &context) {
    if (!context.counters) {
        throw std::invalid_argument(
            "SealBackend::reset_counts: context has no counter state");
    }
    context.counters->counts = OperationCounts{};
}

void SealBackend::set_counting(const EvalContext &context, bool enabled) {
    if (!context.counters) {
        throw std::invalid_argument(
            "SealBackend::set_counting: context has no counter state");
    }
    context.counters->enabled = enabled;
}

SealBackend::OperationCounts
SealBackend::counts(const EvalContext &context) {
    if (!context.counters) {
        throw std::invalid_argument(
            "SealBackend::counts: context has no counter state");
    }
    return context.counters->counts;
}

const char *SealBackend::operation_name(OperationKind kind) {
    switch (kind) {
    case OperationKind::Encrypt:
        return "encrypt";
    case OperationKind::Decrypt:
        return "decrypt";
    case OperationKind::Negate:
        return "negate";
    case OperationKind::Add:
        return "add";
    case OperationKind::Sub:
        return "sub";
    case OperationKind::MulNoRelin:
        return "mul_no_relin";
    case OperationKind::Relinearize:
        return "relinearize";
    case OperationKind::AddPlain:
        return "add_plain";
    case OperationKind::MulPlainScalar:
        return "mul_plain_scalar";
    case OperationKind::MulPlainVector:
        return "mul_plain_vector";
    case OperationKind::Rotate:
        return "rotate";
    case OperationKind::ModSwitch:
        return "mod_switch";
    case OperationKind::LogicalExtAdd:
        return "logical_ext_add";
    case OperationKind::LogicalExtSub:
        return "logical_ext_sub";
    case OperationKind::LogicalExtMul:
        return "logical_ext_mul";
    case OperationKind::LogicalExtMulPlain:
        return "logical_ext_mul_plain";
    case OperationKind::Count:
        break;
    }
    return "unknown";
}


} // namespace laminate::fhe
